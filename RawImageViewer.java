// RawImageViewer
// Visualize raw image data
// @category Visualization
// @menupath Tools.Raw Image Viewer
// @author Ramin Sadre
// @runtime Java



import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import javax.swing.*;
import javax.swing.event.ChangeEvent;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.image.BufferedImage;
import java.util.List;
import java.util.Arrays;
import java.util.Scanner;


public class RawImageViewer extends GhidraScript {
    private static final String[] formats = {
        "Monochrome (1 bit/pixel)",
        "Grayscale (8 bits/pixel)",
        "RGB24 (24 bits/pixel)",
        "RGBA32 (32 bits/pixel)",
        "Bitplanes"
    };
    
    private static final String paramHeader = "$RAWIMAGE (do not modify or add comment after this line),";
    
    private JLabel imageComp;
    private JTextField addressComp;
    private JSpinner planesComp;
    private Address start;
    private int width, height, format, numPlanes;

    private void setDefaultParameters() {
        width = 16;
        height = 16;
        format = 0;
        numPlanes = 1;
    }

    // loads the image parameters from the pre-comment.
    // returns true if successful
    private boolean loadParametersFromComment() {
        String comment = getPreComment(start);
        if (comment==null) {
            return false;
        }
            
        String[] commentLines = comment.split("\n");
        if (!commentLines[commentLines.length-1].startsWith(paramHeader)) {
            return false;
        }
        
        String[] params = commentLines[commentLines.length-1].split(",");
        try {
            int width = Integer.parseInt(params[1]);
            int height = Integer.parseInt(params[2]);
            int format = Integer.parseInt(params[3]);
            int numPlanes = Integer.parseInt(params[4]);
            if(width<0 || width>10000 || height<0 || height>10000
                || format<0 || format>=formats.length || numPlanes<1 || numPlanes>8) {
                    throw new IllegalArgumentException();
            }
            this.width = width; this.height = height; this.format = format; this.numPlanes = numPlanes;
            return true;
        }
        catch (Exception e) {
            return false;
        }
    }
    
    // stores the image parameters in the pre-comment
    private void storeParametersInComment() {
        String params = paramHeader + width + "," + height + "," + format + "," + numPlanes;
        String comment = getPreComment(start);
        if (comment == null) {
            comment = params;
        }
        else {
            String[] commentLines = getPreComment(start).split("\n");
            if (!commentLines[commentLines.length-1].startsWith(paramHeader)) {
                commentLines = Arrays.copyOf(commentLines, commentLines.length + 1);
            }
            commentLines[commentLines.length-1] = params;
            comment = String.join("\n", commentLines);
        }
        start();
        setPreComment(start, comment);
        end(true);
    }
    
    private void setStartAddress(long displacement) {
        start = start.add(displacement);
        onImageChange();
    }

    private void onImageChange() {      
        if(width == 0 || height == 0) {
            imageComp.setIcon(null);
            return;
        }
        
        addressComp.setText("0x"+start.toString());
        
        try {
            // Decode image from memory content
            Memory mem = currentProgram.getMemory();
            BufferedImage img = null;
            switch(format) {
            case 0 -> {
                // 1-bit monochrome (8 pixels per byte, MSB-first)
                byte[] data = new byte[(int) Math.ceil((width * height) / 8.0)];
                mem.getBytes(start, data);
                img = new BufferedImage(width, height, BufferedImage.TYPE_BYTE_BINARY);
                for (int y = 0; y < height; y++) {
                    for (int x = 0; x < width; x++) {
                        int byteIndex = (y * ((width + 7) / 8)) + (x / 8);
                        int bitIndex = 7 - (x % 8);
                        if (byteIndex < data.length) {
                            int bit = (data[byteIndex] >> bitIndex) & 1;
                            int color = bit == 1 ? 0xFFFFFF : 0x000000;
                            img.setRGB(x, y, color);
                        }
                    }
                }
            }
            case 1 -> {
                // 8-bit grayscale
                byte[] data = new byte[width*height];
                mem.getBytes(start, data);
                img = new BufferedImage(width, height, BufferedImage.TYPE_BYTE_GRAY);
                
                int i = 0;
                for (int y = 0; y < height; y++) {
                    for (int x = 0; x < width && i < data.length; x++) {
                        int val = data[i++] & 0xFF;
                        int rgb = (val << 16) | (val << 8) | val;
                        img.setRGB(x, y, rgb);
                    }
                }
            }
            case 2 -> {
                // 24-bit RGB
                byte[] data = new byte[width*height*3];
                mem.getBytes(start, data);
                img = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
                
                int i = 0;
                for (int y = 0; y < height; y++) {
                    for (int x = 0; x < width && i + 2 < data.length; x++) {
                        int r = data[i++] & 0xFF;
                        int g = data[i++] & 0xFF;
                        int b = data[i++] & 0xFF;
                        int rgb = (r << 16) | (g << 8) | b;
                        img.setRGB(x, y, rgb);
                    }
                }
            }
            case 3 -> {
                // 32-bit RGBA
                byte[] data = new byte[width*height*4];
                mem.getBytes(start, data);
                img = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
                
                int i = 0;
                for (int y = 0; y < height; y++) {
                    for (int x = 0; x < width && i + 3 < data.length; x++) {
                        int r = data[i++] & 0xFF;
                        int g = data[i++] & 0xFF;
                        int b = data[i++] & 0xFF;
                        int a = data[i++] & 0xFF;
                        int rgba = (a << 24) | (r << 16) | (g << 8) | b;
                        img.setRGB(x, y, rgba);
                    }
                }
            }
            case 4 -> {
                // Bitplane mode
                int bytesPerPlane = (int) Math.ceil((width * height) / 8.0);
                byte[] data = new byte[numPlanes * bytesPerPlane];
                mem.getBytes(start, data);
                img = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
                
                // make a grayscale palette
                int numColors = 1 << numPlanes;
                int[] palette = new int[numColors];
                for(int i = 0; i < numColors; i++) {
                    int val = (i * 255) / numColors;
                    palette[i] = (val << 16) | (val << 8) | val;
                }
                
                for (int y = 0; y < height; y++) {
                    for (int x = 0; x < width; x++) {
                        int bitIndex = 7 - (x % 8);
                        int byteOffset = (y * (width / 8)) + (x / 8);
                        int colorIndex = 0;
                        for (int p = 0; p < numPlanes; p++) {
                            int planeByteIndex = byteOffset + p * bytesPerPlane;
                            int bit = (data[planeByteIndex] >> bitIndex) & 1;
                            colorIndex |= (bit << p);
                        }
                        int rgb = palette[colorIndex & 0xF];
                        img.setRGB(x, y, rgb);
                    }
                }
            }}
            imageComp.setIcon(new ImageIcon(img));
        }
        catch (Exception e) {
            printerr(e.getMessage());
            imageComp.setIcon(null);
            return;
        }
    }

    @Override
    protected void run() {
        // Use currently selected address as start address
        start = currentAddress;
        if (start == null) {
            printerr("No address selected! Move the cursor to your image data first.");
            return;
        }
        
        if(!loadParametersFromComment()) {
            setDefaultParameters();
        }
        
        // Image window
        JFrame frame = new JFrame("Raw Image Viewer");

        JPanel toolPanel = new JPanel();
        toolPanel.setLayout(new GridLayout(2,1));
    
        JPanel toolPanel1 = new JPanel();
        toolPanel1.setLayout(new FlowLayout(FlowLayout.LEFT));
        toolPanel.add(toolPanel1);
        
        toolPanel1.add(new JLabel("Start address:"));
        
        ((JButton)(toolPanel1.add(new JButton("-4")))).addActionListener((ActionEvent e)->{
            setStartAddress(-4);
        });
        
        ((JButton)(toolPanel1.add(new JButton("-2")))).addActionListener((ActionEvent e)->{
            setStartAddress(-2);
        });
        
        ((JButton)(toolPanel1.add(new JButton("-1")))).addActionListener((ActionEvent e)->{
            setStartAddress(-1);
        });
        
        addressComp = new JTextField(10);
        addressComp.setEditable(false);
        toolPanel1.add(addressComp);
        
        ((JButton)(toolPanel1.add(new JButton("+1")))).addActionListener((ActionEvent e)->{
            setStartAddress(1);
        });
        
        ((JButton)(toolPanel1.add(new JButton("+2")))).addActionListener((ActionEvent e)->{
            setStartAddress(2);
        });
        
        ((JButton)(toolPanel1.add(new JButton("+4")))).addActionListener((ActionEvent e)->{
            setStartAddress(4);
        });

        JPanel toolPanel2 = new JPanel();
        toolPanel2.setLayout(new FlowLayout(FlowLayout.LEFT));
        toolPanel.add(toolPanel2);
        
        // save button
        JButton saveButton = new JButton("Save parameters");
        saveButton.addActionListener((ActionEvent e)->{
            storeParametersInComment();
        });
        toolPanel2.add(saveButton);
        
        // width input field
        toolPanel2.add(new JLabel("Width:"));
        SpinnerNumberModel widthModel = new SpinnerNumberModel(width, 0, 10000, 1);
        JSpinner widthComp = new JSpinner(widthModel);
        widthComp.addChangeListener((ChangeEvent e)->{
            width = (int) widthComp.getValue();
            onImageChange();
        });
        toolPanel2.add(widthComp);
        
        // height input field
        toolPanel2.add(new JLabel("Height:"));
        SpinnerNumberModel heightModel = new SpinnerNumberModel(height, 0, 10000, 1);
        JSpinner heightComp = new JSpinner(heightModel);
        heightComp.addChangeListener((ChangeEvent e)->{
            height = (int) heightComp.getValue();
            onImageChange();
        });
        toolPanel2.add(heightComp);
        
        // format input field
        toolPanel2.add(new JLabel("Format:"));
        JComboBox formatComp = new JComboBox(formats);
        formatComp.setSelectedIndex(format);
        formatComp.addActionListener((ActionEvent e)->{
            format = formatComp.getSelectedIndex();
            planesComp.setEnabled(format==4);
            onImageChange();
        });
        toolPanel2.add(formatComp);
        
        // number of planes input field
        // (only enabled when the corresponding format has been selected)
        toolPanel2.add(new JLabel("Planes:"));
        SpinnerNumberModel planesModel = new SpinnerNumberModel(numPlanes, 1, 8, 1);
        planesComp = new JSpinner(planesModel);
        planesComp.addChangeListener((ChangeEvent e)->{
            numPlanes = (int) planesComp.getValue();
            onImageChange();
        });
        planesComp.setEnabled(format==4);
        toolPanel2.add(planesComp);
        
        frame.getContentPane().add(toolPanel, BorderLayout.NORTH);
        
        imageComp = new JLabel();
        JScrollPane scrollPane = new JScrollPane(imageComp);
        scrollPane.setPreferredSize(new Dimension(640, 400));
        frame.getContentPane().add(scrollPane, BorderLayout.CENTER);
        
        frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        frame.pack();
        frame.setMinimumSize(new Dimension(300, 200));
        frame.setResizable(true);
        frame.setVisible(true);
        
        onImageChange();
    }
}
