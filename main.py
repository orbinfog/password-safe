"""
    Password Safe

    - Jensen Trillo, Version pre-1.0, 23/07/2024

    - ``Python 3.11.6``

    **MIT License, Copyright (c) 2024 Jensen Trillo**
"""
import customtkinter as ctk
from ujson import dumps as json_dumps, loads as json_loads
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from gzip import open as gzip_open
from atexit import register as exit_register
from misc_utils import init_kill_handlers, resource_path
from tkinter_utils import load_fonts, set_opacity
from abc import abstractmethod
from PIL import Image
__version__ = 'pre-1.0'
PATH = resource_path('assets/')  # Absolute asset path for files/resources
DATA_PATH = 'data.json'
MAX_PASS_LENGTH = 16
TRANS = '#feffff'  # Transparent color hex
# Font consts (to make usages smaller)
JB = 'JetBrains Mono NL'
JBB = 'JetBrains Mono NL Bold'
load_fonts((f'{PATH}JetBrainsMonoNL-Regular.ttf', f'{PATH}JetBrainsMonoNL-Bold.ttf'))


class Manager:
    """
        Password manager system.

        Raises
        ------
        - :class:`InvalidToken`: The password does not match
          the one used to encrypt the provided data file

        :param data_path: :class:`str` Path to ``.json`` data file
        :param password: :class:`str` Data encryption password
    """
    def __init__(self, data_path: str, password: str):
        self._path = data_path  # Set data path
        self._key = self.__derive_key(password)  # Get the encryption key using password
        self._data = self.__read()  # Read the JSON file from data path using new encryption key
        # Kill and exit handlers
        init_kill_handlers(lambda *_: self.__write())
        exit_register(self.__write)

    @staticmethod
    def __derive_key(password: str) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=''.join(sorted(password))[::-1].encode(),
                         iterations=480000)
        return urlsafe_b64encode(kdf.derive(password.encode()))

    def change_password(self, password: str):
        """
            Change the password of the manager.

            :param password: :class:`str` New password
        """
        self._key = self.__derive_key(password)  # Get the encryption key using password

    def __read(self) -> dict:
        try:
            with gzip_open(self._path, 'rb') as f:
                # InvalidToken will be raised here
                return json_loads(Fernet(self._key).decrypt(urlsafe_b64encode(f.read())))
        except FileNotFoundError:  # Return empty data dict
            return {}

    def __write(self):
        with gzip_open(self._path, 'wb', 9) as f:
            f.write(urlsafe_b64decode(Fernet(self._key).encrypt(json_dumps(self._data).encode())))

    def sort_services(self, z_a: bool = False) -> dict:
        """
            Returns an alphabetically sorted
            data dictionary.

            :param z_a: :class:`bool` ``False`` for **A-Z**, ``True`` for **Z-A**; `default=False`
            :returns: :class:`dict` Sorted data
        """
        return {k: self._data[k] for k in sorted(self._data, reverse=z_a)}

    # Service methods
    def add_service(self, name: str, data: dict = {}):
        """
            Adds a service; the name is case-sensitive. If
            the service already exists, :class:`KeyError`
            will be raised.

            :param name: :class:`str` Service name; `case-sensitive`
            :param data: :class:`dict` Data to start with; `default={}`
        """
        if name not in self._data:
            self._data[name] = data
        else:  # Already exists
            raise KeyError

    def rename_service(self, name: str, new: str):
        """
            Changes the name of an existing service.

            - If the service does not exist, :class:`KeyError`
              will be raised
            - If the new name conflicts with an existing service,
              :class:`ValueError` will be raised

            :param name: :class:`str` Service name; `case-sensitive`
            :param new: :class:`str` New name; `case-sensitive`
        """
        if new in self._data:  # New name conflicts with existing name
            raise ValueError
        else:
            # Add service with new name and existing data, then delete old instance
            self.add_service(new, self._data[name]), self.delete_service(name)

    def delete_service(self, name: str):
        """
            Deletes the service. :class:`KeyError` will be raised
            if the service does not exist.

            :param name: :class:`str` Service name; `case-sensitive`
        """
        del self._data[name]

    # Account methods
    def add_account(self, service: str, username: str, password: str):
        """
            Add a new account under the service.

            - If the service does not exist, :class:`KeyError`
              will be raised
            - If the account already exists, :class:`ValueError` will be raised

            :param service: :class:`str` Service which account will be under; `case-sensitive`
            :param username: :class:`str` Account username; `case-sensitive`
            :param password: :class:`str` Account password; `case-sensitive`
        """
        if username not in self._data[service]:
            self._data[service][username] = password
        else:  # Account already exists
            raise ValueError

    def edit_account(self, service: str, username: str, change: bool, new: str):
        """
            Edits the username or password of an account.

            - If the service or account does not exist, :class:`KeyError`
              will be raised
            - ``change=True``; If the new username conflicts with an existing account,
              :class:`ValueError` will be raised

            :param service: :class:`str` Service which account is under; `case-sensitive`
            :param username: :class:`str` Account username; `case-sensitive`
            :param change: :class:`bool` ``True`` for editing the **username**, ``False`` for
                **password**
            :param new: :class:`str` New edited value; `case-sensitive`
            :returns: ``change=True``; :class:`bool` ``False`` if the new account name is the same as the current
        """
        if change:  # Edit username
            if new == username:  # No change
                return False
            elif new in self._data[service]:  # Conflicting new username
                raise ValueError
            else:
                # Add new account then delete old instance
                self.add_account(service, new, self._data[service][username])
                self.delete_account(service, username)
        else:  # Edit password
            self._data[service][username] = new

    def delete_account(self, service: str, username: str):
        """
             Deletes the account under the service.
             If the account or service does not exist,
             :class:`KeyError` will be raised.

             :param service: :class:`str` Service which account is under; `case-sensitive`
             :param username: :class:`str` Account username; `case-sensitive`
        """
        del self._data[service][username]


class GUI(ctk.CTk):
    WIDTH, HEIGHT = 450, 575

    class Footer(ctk.CTkFrame):
        def __init__(self, master):
            super().__init__(master, GUI.WIDTH, 40, 0, fg_color='#B8B7B7')
            # Grid weight for column 1 is so sticky works for the version label
            self.grid_propagate(False), self.grid_anchor("w"), self.grid_columnconfigure(1, weight=1)
            (ctk.CTkLabel(self, text='Copyright © 2024 Jensen Trillo', font=(JB, 13),
                          text_color='#282828').grid(row=0, column=0, padx=(15, 0)))
            (ctk.CTkLabel(self, text=f'Version {__version__}', font=(JB, 13), text_color='#282828')
             .grid(row=0, column=1, sticky='e', padx=(0, 15)))

    def __init__(self):
        # Local functions
        def switch_screen(new: ctk.CTkFrame):
            def c():
                new.tkraise()  # Makes it smoother
                self.current_screen.destroy()
                self.current_screen = new

            new.place(x=0, y=0)  # Has to be place(), else flicker will occur
            self.current_screen.tkraise(), self.after(10, c)  # 10ms to stop flicker

        # SCREENS
        # +=====+
        class Screen(ctk.CTkFrame):  # Base Class
            @abstractmethod
            def __init__(self, master):
                super().__init__(master, GUI.WIDTH, GUI.HEIGHT, 0, fg_color='#FBFBFB')
                self.footer = GUI.Footer(self)
                self.footer.place(x=0, y=GUI.HEIGHT - 40)  # Footer

        class MainScreen(Screen):
            def __init__(self, master):
                super().__init__(master)

        class LoginScreen(Screen):
            class Content(ctk.CTkFrame):  # Separate frame to keep it vertically centered
                # self is cnt_self here so that check_password() can access parent self (CTk window)
                def __init__(cnt_self, master, new: bool):
                    def validate(action, text: str) -> bool:  # Validate command
                        if int(action):  # Insert
                            try:
                                text.encode('ascii')  # Raise EncodeError if Unicode
                                # Below maximum password length and does not include spaces
                                if len(text) <= MAX_PASS_LENGTH and ' ' not in text:
                                    return True
                                else:
                                    return False
                            except UnicodeEncodeError:
                                return False
                        else:  # Backspace/deletion
                            return True

                    def check_password(*_):  # Instantiate Manager class
                        pass
                        # switch_screen(MainScreen(self))

                    super().__init__(master, fg_color='transparent')
                    label = ctk.CTkLabel(cnt_self, text=f"{'Create' if new else 'Enter'} your password", font=(JB, 16),
                                         text_color='#000000', fg_color=TRANS)
                    set_opacity(label, color=TRANS), label.grid(row=0, column=0, columnspan=2, sticky='w')
                    # Password Entry
                    cnt_self.password = ctk.CTkEntry(cnt_self, 300, 80, 0, 2, 'transparent', '#E4E4E4', '#B8B7B7',
                                                     '#000000', font=(JB, 28), show='*', validate='key',
                                                     validatecommand=(cnt_self.register(validate), '%d', '%P'))
                    cnt_self.password.bind('<Control-KeyPress-BackSpace>', lambda _: cnt_self.password.delete(0, 'end'))
                    cnt_self.password.bind('<Enter>', check_password)
                    cnt_self.password.grid(row=1, column=0)
                    ctk.CTkButton(cnt_self, 50, 80, 0, fg_color='#55BB33', text='', hover_color='#58C634',
                                  command=check_password, image=ctk.CTkImage(Image.open(f'{PATH}chev_right.png'),
                                                                             size=(42, 42))).grid(row=1, column=1)

            def __init__(self, master, new: bool):
                super().__init__(master), self.grid_propagate(False), self.grid_anchor('c')
                ctk.CTkLabel(self, text='', image=ctk.CTkImage(Image.open(f'{PATH}stripes.png'),
                                                               size=(GUI.WIDTH, GUI.HEIGHT))).pack()
                self.footer.tkraise()  # Footer above stripes background image
                self.Content(self, new).grid(pady=(0, 106))
                if new:  # Label for first time startup warning user to remember password
                    warning = ctk.CTkLabel(self, text="WARNING: Your password cannot be reset if you forget it. This "
                                                      "could lead to permanent data loss! Ensure you keep record of "
                                                      "your password.", font=(JB, 13), width=300, wraplength=300,
                                           justify='left', fg_color=TRANS, text_color='#CC0202')
                    set_opacity(warning, color=TRANS), warning.place(x=40, y=295)

        super().__init__(fg_color='#FBFBFB')
        self.title("Timesheet"),  # self.iconbitmap(f'{PATH}favicon.ico')  # Favicon
        # Dimensions + disable ability to resize
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}"), self.resizable(False, False)
        init_kill_handlers(lambda *_: self.quit())  # GUI kill handlers
        self.current_screen = LoginScreen(self, True)
        self.current_screen.place(x=0, y=0)
        #
        self.mainloop()


if __name__ == '__main__':
    GUI()
