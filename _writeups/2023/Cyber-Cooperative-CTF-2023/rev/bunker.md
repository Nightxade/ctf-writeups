---
layout: writeup
category: Cyber-Cooperative-CTF-2023
chall_description:
points: 100
solves: 300
tags: rev rev/jar
date: 2023-12-19
comments: false
---

You reach a large metal door. It's protected by large yellow bars. There appears to be an panel with a keypad...  

[Bunker.jar](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Cyber-Cooperative-CTF-2023/rev/Bunker.jar)  

---

We're given a .jar file to reverse. [JADX](https://github.com/skylot/jadx) is a great tool for doing exactly that. I'm personally using the GUI version of JADX.  

This is the only Java file in the JADX decompilation:  

```java
package defpackage;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.UIManager;

/* compiled from: bunker.java */
/* renamed from: Bunker  reason: default package */
/* loaded from: Bunker.jar:Bunker.class */
class Bunker extends JFrame implements ActionListener {
    static JFrame f;
    static JTextField l;
    String output = "";

    Bunker() {
    }

    public static void main(String[] strArr) {
        f = new JFrame("Bunker");
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        Bunker bunker = new Bunker();
        l = new JTextField(8);
        l.setEditable(false);
        JButton jButton = new JButton("0");
        JButton jButton2 = new JButton("1");
        JButton jButton3 = new JButton("2");
        JButton jButton4 = new JButton("3");
        JButton jButton5 = new JButton("4");
        JButton jButton6 = new JButton("5");
        JButton jButton7 = new JButton("6");
        JButton jButton8 = new JButton("7");
        JButton jButton9 = new JButton("8");
        JButton jButton10 = new JButton("9");
        JPanel jPanel = new JPanel();
        jButton.addActionListener(bunker);
        jButton2.addActionListener(bunker);
        jButton3.addActionListener(bunker);
        jButton4.addActionListener(bunker);
        jButton5.addActionListener(bunker);
        jButton6.addActionListener(bunker);
        jButton7.addActionListener(bunker);
        jButton8.addActionListener(bunker);
        jButton9.addActionListener(bunker);
        jButton10.addActionListener(bunker);
        jPanel.add(l);
        jPanel.add(jButton);
        jPanel.add(jButton2);
        jPanel.add(jButton3);
        jPanel.add(jButton4);
        jPanel.add(jButton5);
        jPanel.add(jButton6);
        jPanel.add(jButton7);
        jPanel.add(jButton8);
        jPanel.add(jButton9);
        jPanel.add(jButton10);
        f.add(jPanel);
        f.setSize(120, 500);
        f.show();
    }

    public void actionPerformed(ActionEvent actionEvent) {
        this.output += actionEvent.getActionCommand();
        l.setText(this.output);
        if (this.output.length() == 8) {
            System.err.print("USER ENTERED: ");
            System.err.println(this.output);
            l.setText("");
            if (this.output.equals("72945810")) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < "Q^XSNZD^\\WKk\u0004\tnCVKJkTOPYCm_AGLYUEmPZFLCETFP[[E".length(); i++) {
                    sb.append((char) ("Q^XSNZD^\\WKk\u0004\tnCVKJkTOPYCm_AGLYUEmPZFLCETFP[[E".charAt(i) ^ this.output.charAt(i % this.output.length())));
                }
                JOptionPane.showMessageDialog((Component) null, sb.toString());
            } else {
                JOptionPane.showMessageDialog((Component) null, "=== BUNKER CODE INVALID ===");
            }
            this.output = "";
        }
    }
}
```

Seems like the code is just `72945810`.  

Run the program with `java -jar Bunker.jar` and input the code into the numeric keypad to get the flag!  

    flag{bunker_11_says_await_further_instruction}