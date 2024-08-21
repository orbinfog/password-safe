# Password Safe

---

A simple Python 3 GUI program for storing passwords, making it easy to find and manage complex passwords for many accounts.

> [!IMPORTANT]
> All data is encrypted using Fernet AES:
> https://cryptography.io/en/latest/fernet/#implementation  
> The program currently only works on **Windows** operating systems due to `Win32` API usage

---

## Installation
The program was built using `Python 3.11.6` and works on all higher versions. Although not tested, versions down to `3.6` should work. `3.6` is the minimum as that is when *f-strings* were added, which are utilised throughout the GUI.

The following list is of the required dependencies for the program (can also be found in the `requirements.txt`). To install them, run:  
`pip install -r /path/to/requirements.txt`
```
cryptography==42.0.4
customtkinter==5.2.2
misc_utils==1.2
numpy==2.1.0
Pillow==10.4.0
tkinter_utils==1.2.1
ujson==5.9.0
```

Once all dependencies are installed, you can run the program. It is important to note that the program only works for **Windows** operating systems due to using `Win32` API for transparency and Caps Lock detection. Other operating systems will be addressed in the future.
