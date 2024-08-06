"""
    Password Safe

    - Jensen Trillo, Version pre-1.0, 6/08/2024

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
from misc_utils import init_kill_handlers, resource_path, is_empty
from tkinter_utils import load_fonts, set_opacity
from os import path as os_path
from abc import abstractmethod
from PIL import Image, ImageEnhance
__version__ = 'pre-1.0'
PATH = resource_path('assets/')  # Absolute asset path for files/resources
DATA_PATH = 'data.json'
MIN_PASS_LENGTH = 8
MAX_PASS_LENGTH = 16
MAX_SERVICE_LENGTH = 12
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

    def get_services(self) -> dict:
        """
            Returns an alphabetically sorted
            data dictionary.

            :returns: :class:`dict` Sorted data
        """
        return {k: self._data[k] for k in sorted(self._data)}

    # Service methods
    # noinspection PyDefaultArgument
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
        def img_button_brightness(obj: ctk.CTkButton | ctk.CTkLabel, image: Image.Image, size: tuple[int, int],
                                  brightness: float):
            """
                Sets up the necessary bindings for the provided image
                to change brightness (**brighter** ``[>1.0]`` / **darker** ``[<1.0]``) on
                hover.

                - This function will apply the provided :class:`Image.Image` to the widget,
                  so there is no need to specify the ``image=`` keyword in the widget constructor

                :param obj: :class:`ctk.CTkButton` or :class:`ctk.CTkLabel` to apply the bindings to
                :param image: :class:`Image.Image`
                :param size: :class:`tuple` (:class:`int` width ``px``, :class:`int` height ``px``)
                :param brightness: :class:`float` New brightness on hover
            """
            default = ctk.CTkImage(image, size=size)
            hover = ctk.CTkImage(ImageEnhance.Brightness(image).enhance(brightness), size=size)
            obj.configure(image=default, require_redraw=True)
            obj.bind('<Enter>', lambda _: obj.configure(image=hover))
            obj.bind('<Leave>', lambda _: obj.configure(image=default))

        def manager_wrapper(password: str):  # Cleanest way of setting manager class var
            self.manager = Manager(DATA_PATH, password)

        def switch_screen(new: ctk.CTkFrame, preserve: bool = False):
            new.place(x=0, y=0)  # Has to be place(), else flicker will occur
            if not preserve:
                self.current_screen.destroy()
            self.current_screen = new

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
                manager = master.manager  # So it can be accessed anywhere

                # Local Components
                class Services(ctk.CTkScrollableFrame):  # Scrollable frame for containing services and accounts
                    class Service(ctk.CTkFrame):
                        def __init__(self, master, accounts: dict, name: str = None):
                            def dropdown():  # Once clicked
                                def deletion_confirmation():
                                    if not self.delete_step:
                                        delete.configure(border_width=1, text='Confirm deletion')
                                        self.delete_step = 1
                                    else:
                                        manager.delete_service(self.name)
                                        self.grid_forget(), master.service_objects.remove(self)

                                if self.dropdown:  # Collapse dropdown
                                    # Reset everything
                                    self.configure(height=45)
                                    self.button.configure(image=ctk.CTkImage(self.img, size=(20, 20)))
                                else:  # Make dropdown
                                    # Make the frames new height: (# of accounts * 82) + 70
                                    self.configure(height=(height := 115 + (len(self.accounts) * 82)))
                                    self.button.configure(image=ctk.CTkImage(self.img.rotate(270), size=(20, 20)))
                                    # Add the delete service button
                                    self.delete_step = 0
                                    delete = ctk.CTkButton(self, 0, 12, 5, 0, fg_color='transparent', text='Delete service',
                                                  text_color='#CC0202', font=(JB, 12), hover_color='#EAEAEA',
                                                  image=ctk.CTkImage(Image.open(f'{PATH}delete.png'), size=(12, 12)),
                                                  command=deletion_confirmation, border_color='#CC0202'
                                                  )
                                    def w(_):  # Wrapper for resetting deletion step upon hovering off
                                        delete.configure(border_width=0, text='Delete service')
                                        self.delete_step = 0
                                    delete.bind('<Leave>', w), delete.place(x=8, y=height - 34)
                                    # Add new account button
                                    ctk.CTkButton(self, 300, 25, 5, fg_color='#55BB33', text_color='#FAFAFA',
                                                  text=f'Add{" another" if len(self.accounts) > 0 else ""} account',
                                                  font=(JB, 14), hover_color="#5BCA37"
                                                  ).grid(row=1, column=0, padx=45, pady=(45, 0))
                                # --
                                self.dropdown = not self.dropdown

                            super().__init__(master, 390, 45, 10, fg_color='#EAEAEA')
                            self.grid_propagate(False), self.grid_anchor('nw')
                            self.name, self.dropdown, self.accounts = name, False, accounts
                            # Chevron + Service name
                            self.img = ImageEnhance.Brightness(Image.open(f'{PATH}chev_right.png')).enhance(0)
                            self.button = ctk.CTkButton(self, anchor='w', fg_color='#EAEAEA',
                                                        hover_color="#EAEAEA", text='', image=ctk.CTkImage(self.img, size=(20, 20)),
                                                        command=dropdown)
                            self.label = ctk.CTkEntry(self, 160, 20, 0, 0, text_color='#3D3D3D', font=(JB, 20),
                                                     fg_color='transparent', validate='key',
                                                     validatecommand=(self.register(lambda t: len(t) <= MAX_SERVICE_LENGTH), '%P'))
                            # Bindings
                            def clear_err(_=None):
                                self.label.configure(text_color='#3D3D3D'), self.error.place_forget()
                            def reset(change_focus: bool):
                                if change_focus:
                                    self.focus_set()  # Remove focus from entry
                                clear_err(), self.label.delete(0, 'end'), self.label.insert(0, self.name)  # Replace with self.name
                            self.label.bind('<Control-KeyPress-BackSpace>', lambda _: self.label.delete(0, 'end'))
                            self.label.bind('<KeyRelease>', clear_err)
                            # ===========================
                            # Service name error handling
                            self.error = ctk.CTkLabel(self, text='Conflicting name', text_color='#eb2121', font=(JB, 12), fg_color='transparent')
                            def error():
                                self.label.configure(text_color='#ff3333'), self.error.place(x=254, y=8)
                            # ===========================
                            def default():
                                def rename(_):
                                    if self.name != (new := self.label.get()) and not is_empty(new):  # Different name and not empty
                                        try:
                                            manager.rename_service(self.name, new)
                                            self.name = new
                                        except ValueError:  # Conflicting
                                            error()
                                self.label.bind('<KeyRelease-Return>', rename)  # Allow ENTER to rename service
                                self.label.bind('<KeyRelease-Escape>', lambda _: reset(True))
                                self.label.bind('<FocusOut>', lambda _: reset(False))
                            if name:  # Name is provided
                                self.label.insert(0, name), default()
                            else:  # Add new service
                                def add(_):
                                    if not is_empty(new := self.label.get()):
                                        try:
                                            manager.add_service(new)  # KeyError
                                            for n, id in bindings:
                                                self.label.unbind(n, id)
                                            default(), self.button.configure(state='normal'), self.focus_set()
                                            master.adding, self.name = False, new
                                            services.sort(sorting.cget('text') != 'A-Z')  # Re-sort the order once confirmed
                                        except KeyError:  # Already exists
                                            error()
                                def remove(_):
                                    try:
                                        self.grid_forget(), master.service_objects.remove(self)
                                        master.adding = False
                                    except ValueError:
                                        pass
                                self.button.configure(state='disabled')
                                bindings = {
                                    (s := '<KeyRelease-Return>', self.label.bind(s, add)),  # Add service upon ENTER
                                    (s := '<KeyRelease-Escape>', self.label.bind(s, remove)),
                                    (s := '<FocusOut>', self.label.bind(s, remove))
                                }
                            self.button.place(x=4, y=8), self.label.place(x=30, y=8)

                    def __init__(self, master):
                        super().__init__(master, 390, 350, 0, fg_color='transparent')
                        self.adding, self.service_objects = False, []
                        for i, (service, accounts) in enumerate(manager.get_services().items()):
                            self.service_objects.append(o := self.Service(self, accounts, service)), o.grid(row=i, column=0, pady=(0, 5))

                    def sort(self, z_a: bool = False): 
                        addition = False  # If the user is in the process of adding a new service
                        if not self.service_objects[-1].name:  # Last list item name is None (not added yet)
                            addition = self.service_objects[-1]
                            self.service_objects.pop(-1)
                        self.service_objects = [o for o in sorted(self.service_objects, reverse=z_a, 
                                                                  key=lambda o: o.name)]
                        for i, o in enumerate(self.service_objects, 1 if addition else 0):
                            # if o.winfo_ismapped():
                            o.grid_configure(row=i)
                        if addition:  # Re-add the addition service box
                            self.service_objects.append(addition)

                    def add(self):
                        if not self.adding:
                            self.adding = True
                            new = self.Service(self, {})
                            new.grid(row=0, column=0, pady=(0, 5)), new.label.focus_set()
                            for i, o in enumerate(self.service_objects, 1):
                                o.grid_configure(row=i)
                            self.service_objects.append(new)
                    
                    def query(self, q: str):
                        for o in self.service_objects:
                            if o.name.startswith(q):  # If the objects name starts with the query
                                o.grid()
                            else:  # Else remove it (keeps grid configuration)
                                o.grid_remove()

                class Search(ctk.CTkFrame):  # Searchbar
                    def __init__(self, master):
                        super().__init__(master, 185, 35, 5, 2, fg_color='transparent',
                                         border_color='#000000')
                        # Search icon
                        img = ctk.CTkLabel(self, 35, 35, 0, fg_color='#000000', bg_color=TRANS,
                                           text='', compound='left',
                                           image=ctk.CTkImage(Image.open(f'{PATH}search.png'), size=(20, 20)))
                        set_opacity(img, color=TRANS), img.place(x=2, y=0)  # Remove BG and place
                        # Entry box for query
                        self.query = ctk.CTkEntry(self, 147, 30, 0, 0, fg_color='transparent', validate='key', 
                                                  validatecommand=(self.register(lambda t: len(t) <= MAX_SERVICE_LENGTH), '%P'),
                                                  text_color='#212121', font=(JB, 18))
                        self.query.bind('<KeyRelease>', lambda _: services.query(self.query.get()))
                        self.query.bind('<Control-KeyPress-BackSpace>', lambda _: self.query.delete(0, 'end'))
                        self.query.place(x=35, y=2)

                class AddService(ctk.CTkFrame):
                    def __init__(self, master):
                        # Label and button with the text being '+' doesn't work as the plus exceeds the 35x35px
                        # dimensions. Because of this, a frame with the image on top is used, which means the frame
                        # and label img both need mouse bindings
                        super().__init__(master, 35, 35, 12, fg_color='#55BB33', cursor='hand2')
                        self.grid_propagate(False), self.grid_anchor('center')
                        plus = ctk.CTkLabel(self, text='+', text_color='#FFFFFF', font=(JBB, 32), fg_color=TRANS,
                                            bg_color=TRANS)
                        set_opacity(plus, color=TRANS), plus.grid(padx=(0, 1), pady=(0, 2))
                        for o in {self, plus}:
                            # Hover colours
                            o.bind('<Enter>', lambda _: self.configure(fg_color='#5BCA37'))  # Hover over
                            o.bind('<Leave>', lambda _: self.configure(fg_color='#55BB33'))  # Exit
                            o.bind('<Button-1>', lambda _: services.add())

                # ========================================================================
                super().__init__(master), self.grid_propagate(False), self.grid_anchor('n')
                ctk.CTkLabel(self, text='Your services', text_color='#000000', font=(JB, 24)).grid(
                    row=0, column=0, columnspan=3, sticky='w', pady=(30, 2))  # Services header text
                #
                # SECOND ROW BUTTONS
                Search(self).grid(row=1, column=0, sticky='w', padx=(0, 100))
                # Sorting button
                sorting = ctk.CTkButton(self, 75, 35, 5, 2, fg_color='transparent', border_color='#000000',
                              hover_color='#FFFFFF', text='A-Z', text_color='#000000', font=(JBB, 20),
                              image=ctk.CTkImage(Image.open(f'{PATH}sort.png'), size=(12, 10)),
                              command=lambda: (
                                  sorting.configure(text=(order := 'A-Z' if sorting.cget('text') == 'Z-A' else 'Z-A')),
                                  services.sort(order != 'A-Z')
                              ))
                sorting.grid(row=1, column=1, sticky='e')
                AddService(self).grid(row=1, column=2, sticky='e')  # Add account button
                # --
                services = Services(self)
                services.grid(row=2, column=0, columnspan=3, pady=(10, 0))
                # Change Password footer button
                ctk.CTkButton(self, GUI.WIDTH, 40, 0, text='Change the master password', font=(JB, 12),
                              text_color='#343434', fg_color='#E4E3E3', hover_color='#d8d8d8',
                              # provide this MainScreen instance, so it can return to the same one upon change
                              command=lambda: switch_screen(LoginScreen(master, True, self), True),
                              image=ctk.CTkImage(Image.open(f'{PATH}edit.png'), size=(16, 16))).place(x=0, y=GUI.HEIGHT - 80)

        class LoginScreen(Screen):
            class Content(ctk.CTkFrame):  # Separate frame to keep it vertically centered
                # noinspection PyMethodParameters
                # self is c_self here so switch_screen() can access parent CTk
                def __init__(c_self, master, new: bool, change: MainScreen = None):
                    def validate(action, text: str) -> bool:  # Validate command
                        if int(action):  # Insert
                            try:
                                text.encode('ascii')  # Raise EncodeError if Unicode
                                # Below maximum password length and does not include spaces
                                return len(text) <= MAX_PASS_LENGTH and ' ' not in text
                            except UnicodeEncodeError:
                                return False
                        else:  # Backspace/deletion
                            return True

                    def check_password(*_):  # Instantiate Manager class
                        def error():
                            c_self.password.configure(border_color='#ff3333')
                            c_self.button.configure(fg_color='#ff3333', state='disabled')

                        if len(entry := c_self.password.get()) < MIN_PASS_LENGTH:
                            error()
                            return
                        if change:  # Change password to new one
                            # noinspection PyUnresolvedReferences
                            self.manager.change_password(entry)
                            switch_screen(change)  # Switch back to previous MainScreen (change var)
                            return
                        elif new:  # Skip checking as this is the creation of the password
                            manager_wrapper(entry)
                        else:  # Not new - login
                            try:
                                manager_wrapper(entry)
                            except InvalidToken:
                                error()
                                return  # Return before reaching switch_screen
                        # noinspection PyTypeChecker
                        switch_screen(MainScreen(self))  # Successful

                    def reset(e):
                        # If the event character is valid, and above 0 characters, reset to normal colours
                        if len(c_self.password.get()) > 0 and validate(1, e.char):
                            c_self.password.configure(border_color='#B8B7B7')
                            c_self.button.configure(fg_color='#55BB33', state='normal')

                    super().__init__(master, fg_color='transparent')
                    label = ctk.CTkLabel(c_self, text=f"{'Change' if change else 'Create' if new else 'Enter'} "
                                                      f"your password", font=(JB, 16), text_color='#000000', fg_color=TRANS)
                    set_opacity(label, color=TRANS), label.grid(row=0, column=0, columnspan=2, sticky='w')
                    # Password Entry
                    c_self.password = ctk.CTkEntry(c_self, 300, 80, 0, 2, 'transparent', '#E4E4E4', '#B8B7B7',
                                                     '#000000', font=(JB, 28), show='*', validate='key',
                                                   validatecommand=(c_self.register(validate), '%d', '%P'))
                    c_self.password.bind('<Control-KeyPress-BackSpace>', lambda e: (reset(e),
                                                                                    c_self.password.delete(0, 'end')))
                    c_self.password.bind('<KeyRelease-Return>', check_password)
                    c_self.password.bind('<KeyRelease>', reset)
                    c_self.password.grid(row=1, column=0)
                    c_self.button = ctk.CTkButton(c_self, 50, 80, 0, fg_color='#55BB33', text='',
                                                  hover_color='#5BCA37', command=check_password,
                                                  image=ctk.CTkImage(Image.open(
                                                      f'{PATH}{"edit" if change else "chev_right"}.png'),
                                                      size=(22, 22) if change else (42, 42)))
                    c_self.button.grid(row=1, column=1)

            def __init__(self, master, new: bool, change: MainScreen = None):
                super().__init__(master), self.grid_propagate(False), self.grid_anchor('center')
                # Stripes background
                ctk.CTkLabel(self, text='', image=ctk.CTkImage(Image.open(f'{PATH}stripes.png'),
                                                               size=(GUI.WIDTH, GUI.HEIGHT))).pack()
                self.footer.tkraise()  # Footer above stripes background image
                self.Content(self, new, change).grid(pady=(0, 106))
                placement = (45, 363)  # Default X/Y for Caps Lock
                if change:  # Back button
                    back = ctk.CTkButton(self, 32, 32, 0, text='', fg_color=TRANS,
                                         hover_color=TRANS, command=lambda: switch_screen(change))
                    img_button_brightness(back, Image.open(f'{PATH}back_arrow.png'), (32, 32), 1.3)
                    set_opacity(back, color=TRANS), back.place(x=45, y=45)
                if new:  # Label for first time startup warning user to remember password
                    length = ctk.CTkLabel(self, text=f'The password must be between {MIN_PASS_LENGTH} and '
                                                     f'{MAX_PASS_LENGTH} characters.', font=(JB, 12), text_color='#000000',
                                          fg_color=TRANS)
                    warning = ctk.CTkLabel(self, text="WARNING: Your password cannot be reset if you forget it. This "
                                                      "could lead to permanent data loss! Ensure you keep record of "
                                                      "your password.", font=(JB, 12), wraplength=350,
                                           justify='left', fg_color=TRANS, text_color='#CC0202')
                    set_opacity(length, color=TRANS), length.place(x=50, y=290)
                    set_opacity(warning, color=TRANS), warning.place(x=50, y=315)
                else:  # Standard placement
                    placement = (45, 290)
                # --
                try:  # Try to set up Caps Lock warning for Windows
                    from ctypes import windll
                    def listen():
                        if windll.user32.GetKeyState(0x14):  # Turned on
                            self.caps_lock.place(x=placement[0], y=placement[1])
                        else:
                            self.caps_lock.place_forget()
                        self.after(1, listen)
                    self.caps_lock = ctk.CTkLabel(self, text='Caps Lock is On', text_color='#4046b6', font=(JBB, 12),
                                                  fg_color=TRANS, image=ctk.CTkImage(Image.open(f'{PATH}warning.png'),
                                                                                     size=(18, 18)), compound='left', padx=5)
                    set_opacity(self.caps_lock, color=TRANS)
                    self.after(1, listen)
                except (Exception,):
                    pass

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        super().__init__(fg_color='#FBFBFB')
        # ctk.set_appearance_mode("dark")
        self.title("Password Safe"), self.iconbitmap(f'{PATH}favicon.ico')  # Favicon
        # Dimensions + disable ability to resize
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}"), self.resizable(False, False)
        init_kill_handlers(lambda *_: self.quit())  # GUI kill handlers
        # If path exists, it is not new, else it is
        self.current_screen = LoginScreen(self, not os_path.exists(DATA_PATH))
        self.current_screen.place(x=0, y=0)
        #
        self.mainloop()


if __name__ == '__main__':
    GUI()
