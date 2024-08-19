"""
    Password Safe

    - Jensen Trillo, Version pre-1.0, 19/08/2024

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
from PIL import Image, ImageEnhance
from numpy import array as np_array
# DO NOT TOUCH section
__version__ = 'pre-1.0'
PATH = resource_path('assets/')  # Absolute asset path for files/resources
TRANS = '#feffff'  # Transparent color hex
# Font consts (to make usages smaller)
JB = 'JetBrains Mono NL'
JBB = 'JetBrains Mono NL Bold'
load_fonts((f'{PATH}JetBrainsMonoNL-Regular.ttf', f'{PATH}JetBrainsMonoNL-Bold.ttf'))
# --
DATA_PATH = 'data.json'
MIN_PASS_LENGTH = 8
MAX_PASS_LENGTH = 16
MAX_SERVICE_LENGTH = 12
MAX_USER_LENGTH = 128
INACTIVITY_PERIOD = 120  # In Seconds


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
        init_kill_handlers(lambda *_: self.write())
        exit_register(self.write)

    @staticmethod
    def __derive_key(password: str) -> bytes:
        kdf = PBKDF2HMAC(hashes.SHA256(), 32, ''.join(sorted(password))[::-1].encode(), 480000)
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

    def write(self):
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
    def add_service(self, name: str, data):
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
        self._data.pop(name)

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

    class Screen(ctk.CTkFrame):  # Base abstract class
        def __init__(self, master):
            super().__init__(master, GUI.WIDTH, GUI.HEIGHT, 0, fg_color='#FBFBFB')
            self.footer = GUI.Footer(self)
            self.footer.place(x=0, y=GUI.HEIGHT - 40)  # Footer

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
        # 〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉
        # LOCAL UTILITY FUNCTIONS
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

        def ctrl_backspace_bind(obj):
            obj.bind('<Control-KeyPress-BackSpace>', lambda _: obj.delete(0, 'end'))

        show = ctk.CTkImage(Image.open(f'{PATH}show.png'), size=(20, 20))
        hide = ctk.CTkImage(Image.open(f'{PATH}hide.png'), size=(20, 20))

        class Visibility(ctk.CTkButton):
            def __init__(self, master, entry: ctk.CTkEntry, **kw):
                super().__init__(master, height=20, fg_color=TRANS, text='', hover_color=TRANS,
                                 command=lambda: toggle_visibility(entry, self), image=hide, **kw)
                set_opacity(self, color=TRANS)

        def toggle_visibility(entry: ctk.CTkEntry, obj: Visibility):
            if not is_empty(entry.get()):
                if entry.cget('show'):
                    entry.configure(show=''), obj.configure(image=show)
                else:
                    entry.configure(show='*'), obj.configure(image=hide)

        # 〉〉〉〉〉〉〉〉〉〉〉〉〉〉
        # SCREENS
        class MainScreen(self.Screen):
            def __init__(self, master):
                manager = master.manager  # So it can be accessed anywhere

                # Local Components
                class Services(ctk.CTkScrollableFrame):  # Scrollable frame for containing services and accounts
                    class Service(ctk.CTkFrame):
                        # noinspection PyUnresolvedReferences
                        class Account(ctk.CTkFrame):
                            def __init__(self, _master, username: str = None, password: str = None,
                                         focus: bool = False):
                                # noinspection PyUnresolvedReferences
                                class EntryObj(ctk.CTkEntry):
                                    def __init__(self, _master, username_: bool, **kwargs):
                                        super().__init__(_master, 240, 25, 0, 0, placeholder_text_color='#919191',
                                                         fg_color='transparent', validate='key',
                                                         validatecommand=_master.validation, **kwargs)
                                        self.username_, self.binding = username_, None
                                        self.bind('<KeyRelease-Escape>',
                                                  lambda _: _master.handle_change(True, self, True))
                                        self.bind('<FocusOut>',
                                                  lambda _: _master.handle_change(False, self, focusout=True))
                                        ctrl_backspace_bind(self)
                                        if username:  # User & pass is provided
                                            self.bind('<KeyRelease-Return>', lambda _:
                                                      _master.focus_set() if _master.rename(self) else None)

                                    def unconfirmed_binding(self, obj):
                                        # Added to bindings() so they can be removed on create()
                                        # all() in lambda otherwise it would be called twice for handle_change()
                                        self.binding = self.bind('<KeyRelease-Return>', lambda _: (
                                            # Create if both inputs are full
                                            self.master.create(enter=True) if all(not is_empty(x) for x in
                                                                                  {self.master.username_obj.get(),
                                                                                   self.master.password_obj.get()})
                                            # Otherwise change focus to other input if not empty or conflicting
                                            else obj.focus_set() if (not is_empty(self.get()) and not self.master.error)
                                            else None
                                        ))

                                    def remove_binding(self):
                                        self.unbind('<KeyRelease-Return>', self.binding)
                                        self.bind('<KeyRelease-Return>', lambda _: (
                                            self.master.focus_set() if self.master.rename(self)
                                            else None
                                        ))
                                # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                                super().__init__(_master, 300, 82, 5, fg_color='#FFFFFF')
                                self.grid_propagate(False), self.grid_anchor('center')
                                self.username, self.password, self.error = username, password, False
                                self.validation = (self.register(lambda t: ' ' not in t and len(t) <= MAX_USER_LENGTH),
                                                   '%P')
                                # IMAGES
                                garbage = ctk.CTkImage(i := Image.open(f'{PATH}garbage.png'))
                                garbage_h = np_array(i)
                                garbage_h[..., :-1] = (255, 10, 10)
                                garbage_h = ctk.CTkImage(Image.fromarray(garbage_h))
                                # --
                                # Username + password entries
                                self.username_obj = EntryObj(self, True, placeholder_text='Username',
                                                             text_color='#2A295E', font=(JB, 20))
                                self.password_obj = EntryObj(self, False, placeholder_text='Password',
                                                             text_color='#0E0D2C', font=(JBB, 20), show='*')
                                # Buttons
                                self.visibility = Visibility(self, self.password_obj, width=20, anchor='w')
                                self.visibility.grid(row=1, column=1, sticky='w', padx=(12, 0))
                                (delete := ctk.CTkButton(self, 18, 18, anchor='w', fg_color=TRANS,
                                                         hover_color=TRANS, text='', image=garbage,
                                                         command=lambda: (
                                        (manager.delete_account(self.master.name, self.username), self.__delete())
                                        if self.username else
                                        (self.__delete(), self.master.add_acc.configure(state='normal',
                                                                                        fg_color='#55BB33'))
                                ))).grid(row=0, column=1, padx=(13, 0))
                                set_opacity(delete, color=TRANS)
                                delete.bind('<Enter>', lambda _: delete.configure(image=garbage_h))
                                delete.bind('<Leave>', lambda _: delete.configure(image=garbage))

                                # BINDINGS
                                self.username_obj.bind('<KeyRelease>', self.__check_conflicting)
                                if username:  # User & pass is provided
                                    self.username_obj.insert(0, username), self.password_obj.insert(0, password)
                                else:  # Bindings have to be added here
                                    self.username_obj.unconfirmed_binding(self.password_obj)
                                    self.password_obj.unconfirmed_binding(self.username_obj)
                                # --
                                self.username_obj.grid(row=0, column=0)
                                self.password_obj.grid(row=1, column=0)
                                if focus:
                                    self.username_obj.focus_set()

                            def __check_conflicting(self, _):
                                # Conflicting name (modified from current self.username)
                                if (self.username != (new := self.username_obj.get()) and
                                        new in manager.get_services()[self.master.name]):
                                    self.username_obj.configure(text_color='#ff3333')
                                    self.error = True
                                else:  # Clear conflicting error message
                                    self.username_obj.configure(text_color='#2A295E')
                                    self.error = False

                            def __delete(self):
                                self.master.accounts.remove(self)
                                self.username_obj.configure(text_color='#2A295E')  # Reset error text color
                                if not len(manager.get_services()[self.master.name]):  # Change to 'Add Account'
                                    self.master.add_acc.configure(text=f'Add account')
                                self.destroy(), self.master.shift_accounts(False)

                            def rename(self, obj) -> bool:
                                # Different name and not empty
                                if ((self.username if obj.username_ else self.password) != (new := obj.get()) and
                                        not is_empty(new)):
                                    try:
                                        manager.edit_account(self.master.name, self.username, obj.username_, new)
                                        if obj.username_:
                                            self.username = new
                                        else:
                                            self.password = new
                                    except ValueError:  # Conflicting username
                                        # Error handled in __check_conflicting
                                        return False
                                return True  # return for ENTER bind

                            # Convert into proper account - creates in Manager
                            def create(self, focus: bool = True, enter: bool = False):
                                if not self.error:  # No conflicting username
                                    self.username, self.password = self.username_obj.get(), self.password_obj.get()
                                    self.master.add_acc.configure(state='normal', fg_color='#55BB33',
                                                                  text=f'Add another account')  # >=1 account
                                    manager.add_account(self.master.name, self.username, self.password)
                                    # Change bindings
                                    self.username_obj.remove_binding(), self.password_obj.remove_binding()
                                    if focus:
                                        self.focus_set()
                                elif enter:
                                    self.username_obj.focus_set()

                            def handle_change(self, change_focus: bool, obj, escape: bool = False,
                                              focusout: bool = False):
                                if self.username:
                                    obj.xview_moveto(0)  # Move to X=0
                                    if change_focus:
                                        self.focus_set()  # Remove focus from entry
                                    # If ESC, conflicting name or empty, reset
                                    if escape or self.error or is_empty(obj.get()):
                                        self.username_obj.configure(text_color='#2A295E')  # Reset error text color
                                        # Replace text
                                        obj.delete(0, 'end')
                                        obj.insert(0, self.username if obj.username_ else self.password)
                                    else:  # Otherwise confirm rename
                                        self.rename(obj)
                                # Remove service if either username or password are empty or ESC or conflicting username
                                # (when in unconfirmed state)
                                elif (any(is_empty(x) for x in {self.username_obj.get(), self.password_obj.get()}) or
                                      escape or self.error):
                                    # Cancel event if not confirmed so focus between entries is allowed
                                    if focusout and str(self) in str(self.focus_get()):
                                        return
                                    self.master.add_acc.configure(state='normal', fg_color='#55BB33')
                                    self.__delete()
                                # Save account once user and password
                                else:
                                    # Allow focus between entries without confirming
                                    if focusout and str(self) in str(self.focus_get()):
                                        return
                                    self.create(not focusout)  # Set focus if not FOCUSOUT

                        def __init__(self, _master, accounts: dict, name: str = None):
                            # Has to be own class for its identifying name in mouse_off()
                            class AddAccount(ctk.CTkButton):
                                def __init__(self, m):
                                    super().__init__(m, 300, 25, 5, fg_color='#55BB33', text_color='#FAFAFA',
                                                     text=f'Add{" another" if len(accounts) > 0 else ""} account',
                                                     font=(JB, 14), hover_color="#5BCA37", command=m.add_acc,
                                                     text_color_disabled='#FAFAFA')
                            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                            super().__init__(_master, 390, 45, 10, fg_color='#EAEAEA')
                            self.grid_propagate(False), self.grid_anchor('nw')
                            self.name, self.delete_step, self.dropdown, self.f_dropdown = name, False, False, True
                            self.accounts = []  # List of Account objects
                            # Chevron + Service name
                            self.img = ImageEnhance.Brightness(Image.open(f'{PATH}chev_right.png')).enhance(0)
                            self.button = ctk.CTkButton(self, anchor='w', fg_color='#EAEAEA',
                                                        hover_color="#EAEAEA", text='', command=self.__toggle_dropdown,
                                                        image=ctk.CTkImage(self.img, size=(20, 20)))
                            self.label = ctk.CTkEntry(self, 160, 20, 0, 0, text_color='#3D3D3D', font=(JB, 20),
                                                      fg_color='transparent', validate='key',
                                                      validatecommand=(self.register(
                                                          lambda t: len(t) <= MAX_SERVICE_LENGTH), '%P'))
                            # Dropdown objects
                            self.delete = ctk.CTkButton(self, 0, 12, 5, 0, fg_color='transparent',
                                                        text='Delete service', text_color='#CC0202', font=(JB, 12),
                                                        hover_color='#EAEAEA', image=
                                                        ctk.CTkImage(Image.open(f'{PATH}delete.png'), size=(12, 12)),
                                                        command=self.__deletion_confirmation, border_color='#CC0202')
                            self.add_acc = AddAccount(self)
                            self.error = (  # Tuple of error lambda, clear error lambda & object
                                lambda: (self.label.configure(text_color='#ff3333'), self.error[2].place(x=268, y=8)),
                                lambda: (self.label.configure(text_color='#3D3D3D'), self.error[2].place_forget()),
                                ctk.CTkLabel(self, text='Already exists', text_color='#eb2121', font=(JB, 12))
                            )

                            # BINDINGS
                            def del_reset(_):  # Wrapper for resetting deletion step upon hovering off
                                self.delete.configure(border_width=0, text='Delete service')
                                self.delete_step = False
                            self.delete.bind('<Leave>', del_reset),

                            def double(_):
                                _master.double = True
                                self.label.focus_set()
                            self.bind('<Double-Button-1>', double)
                            self.label.bind('<KeyRelease-Escape>', lambda _: self.handle_change(True, True))
                            self.label.bind('<FocusOut>', lambda _: self.handle_change(False))
                            ctrl_backspace_bind(self.label), self.label.bind('<KeyRelease>', self.__check_conflicting)
                            # ░░░░░░░░░░░░░░░░░░░░░░░░░░░
                            if name:  # Name is provided
                                self.label.insert(0, name)
                                self.label.bind('<KeyRelease-Return>',
                                                lambda _: self.focus_set() if self.__rename() else None)

                            else:  # Add new service
                                self.button.configure(state='disabled')
                                # Create service upon ENTER
                                self.binding = self.label.bind('<KeyRelease-Return>', self.__create)
                            # --
                            self.button.place(x=4, y=8), self.label.place(x=30, y=8)

                        def __toggle_dropdown(self):
                            if self.dropdown:  # Collapse dropdown
                                for o in self.accounts:  # Hide all account passwords
                                    o.password_obj.configure(show='*'), o.visibility.configure(image=hide)
                                # Reset everything after 1ms, so that if you have an unconfirmed service,
                                # it can be handled first
                                self.after(1, lambda: (
                                    self.configure(height=45),
                                    self.button.configure(image=ctk.CTkImage(self.img, size=(20, 20)))
                                ))
                            else:  # Make dropdown
                                self.configure(  # Make the frames height: 115 + (# of accounts * (82 + 3px Y padding))
                                    height=(height := 115 + ((l := len(manager.get_services()[self.name])) * 85)))
                                self.button.configure(image=ctk.CTkImage(self.img.rotate(270), size=(20, 20)))
                                self.delete.place(x=8, y=height - 34)
                                if self.f_dropdown:  # Create only on first time
                                    self.f_dropdown = False
                                    # Needs 44px of Y padding, so instead of changing it on every update to the first
                                    # row item, just have 0x0px frame in row 0 with the necessary Y padding
                                    ctk.CTkFrame(self, 0, 0).grid(row=0, pady=(44, 0))
                                    for i, (username, password) in (  # Place accounts
                                            enumerate(manager.get_services()[self.name].items(), 1)):
                                        self.accounts.append((o := self.Account(self, username, password)))
                                        o.grid(row=i, column=0, pady=(0, 3))
                                    self.add_acc.grid(row=l + 1, padx=45)
                            # --
                            self.dropdown = not self.dropdown

                        # noinspection PyUnresolvedReferences
                        def __deletion_confirmation(self):
                            if not self.delete_step:
                                self.delete.configure(border_width=1, text='Confirm deletion')
                                self.delete_step = True
                            else:
                                manager.delete_service(self.name)
                                self.destroy(), self.master.service_objects.remove(self)
                                if len(_s := manager.get_services()) == 1:  # Only one service, clear search query
                                    search.query.delete(0, 'end'), self.master.query()
                                if not len(_s):  # No services at all
                                    self.master.special_message(self.master.no_services, True, '#40ACE3')
                                elif q := search.query.get():  # Enough services, check for results
                                    # Has to redo query in case the deleted service is the only one left,
                                    # so that query can place 'No Results' msg
                                    self.master.query(q)
                                # self.master._parent_canvas.yview_moveto(v)
                                search.state_check(_s)  # Check if # of services allows search to be enabled

                        def __check_conflicting(self, _):
                            # Conflicting name (modified from current self.name)
                            if self.name != (new := self.label.get()) and new in manager.get_services():
                                self.error[0]()  # Error lambda
                            else:  # Clear conflicting error message
                                self.error[1]()  # Clear err lambda

                        # noinspection PyUnresolvedReferences
                        def __rename(self, _=None) -> bool:
                            # Different name and not empty
                            if self.name != (new := self.label.get()) and not is_empty(new):
                                try:
                                    manager.rename_service(self.name, new)  # ValueError
                                    self.name = new
                                    if q := search.query.get():  # Search query active
                                        self.master.query(q)
                                    services.sort(sorting.cget('text') != 'A-Z')  # Re-sort the order
                                except ValueError:  # Conflicting
                                    # Error handled in __check_conflicting
                                    return False
                            return True  # return for ENTER bind

                        def __create(self, _=None) -> bool:  # Convert into confirmed service - creates in Manager
                            if not is_empty(new := self.label.get()):
                                try:
                                    manager.add_service(new, {})  # KeyError
                                    self.label.unbind('<KeyRelease-Return>', self.binding)  # Remove ENTER binding
                                    self.label.bind('<KeyRelease-Return>',  # ENTER to rename service
                                                    lambda _: self.focus_set() if self.__rename() else None)
                                    self.button.configure(state='normal'), self.focus_set()
                                    self.master.adding, self.name = False, new
                                    services.sort(sorting.cget('text') != 'A-Z')  # Re-sort the order
                                    search.state_check()  # Check if # of services allows search to be enabled
                                except KeyError:  # Already exists
                                    return True

                        def add_acc(self):
                            self.add_acc.configure(state='disabled', fg_color='#b0b0b0')
                            self.accounts.append(self.Account(self, focus=True))
                            self.shift_accounts(True)

                        def shift_accounts(self, add: bool):
                            # Shift objects
                            for i, o in enumerate(self.accounts, 1):
                                o.grid_configure(row=i, pady=(0, 3))
                            self.add_acc.grid_configure(row=len(self.accounts) + 1)
                            # 82 + 3px Y padding
                            self.configure(height=(height := self.winfo_height() + (85 if add else -85)))
                            self.delete.place_configure(y=height - 34)

                        # noinspection PyUnresolvedReferences
                        def handle_change(self, change_focus: bool, escape: bool = False):
                            if self.name:  # Reset
                                if change_focus:
                                    self.focus_set()  # Remove focus from entry
                                # --
                                # If ESC, conflicting name or empty, reset
                                if escape or self.error[2].winfo_ismapped() or is_empty(self.label.get()):
                                    self.error[1]()  # Clear err lambda
                                    # Replace with self.name
                                    self.label.delete(0, 'end'), self.label.insert(0, self.name)
                                else:  # Otherwise confirm rename
                                    self.__rename()
                            else:  # Unconfirmed service
                                if escape or is_empty(self.label.get()):  # If empty or ESC, remove it
                                    pass  # Go to removing
                                else:  # Otherwise confirm it
                                    if not self.__create():  # If not conflicting
                                        return  # Return before removing
                                # --
                                try:
                                    self.destroy(), self.master.service_objects.remove(self)
                                    if not len(manager.get_services()):  # Place no services message
                                        self.master.special_message(self.master.no_services, True, '#40ACE3')
                                    self.master.adding = False
                                except ValueError:
                                    pass

                    def __init__(self, _master):
                        class Start(ctk.CTkFrame):  # For when there are 0 services
                            def __init__(self, m):
                                super().__init__(m, 390, 348, 0, fg_color='transparent')
                                self.grid_propagate(False), self.grid_anchor('center')
                                ctk.CTkLabel(self, text='You have 0 services', text_color='#3295C7',
                                             font=(JB, 20)).grid(row=0)
                                ctk.CTkButton(self, 230, 25, 5, fg_color='#55BB33', text_color='#FAFAFA',
                                              text=f'Add service', font=(JB, 14), hover_color="#5BCA37",
                                              command=lambda: services.add(),
                                              ).grid(row=1, pady=(6, 0))
                        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        super().__init__(_master, 390, 350, 0, fg_color='transparent')
                        # So border goes fully around
                        self._scrollbar.configure(bg_color=TRANS), set_opacity(self._scrollbar, color=TRANS)
                        # 'double' for double click to set focus, 'adding' for in the process of adding new service
                        self.double, self.adding, self.service_objects = False, False, []
                        # Special messages
                        self.no_results = ctk.CTkLabel(self, 390, 348, text='No results...', text_color='#eb2121',
                                                       font=(JB, 20))
                        self.no_services = Start(self)
                        # --
                        for i, (service, accounts) in enumerate((s := manager.get_services()).items()):
                            # Place services
                            self.service_objects.append(o := self.Service(self, accounts, service))
                            o.grid(row=i, column=0, pady=(0, 5))
                        if not len(s):  # No services
                            self.special_message(self.no_services, True, '#40ACE3')

                    def special_message(self, obj, _show: bool, color: str = None):
                        if _show:
                            self.configure(width=388, height=348, border_width=2, border_color=color,
                                           scrollbar_button_color=TRANS)
                            obj.grid()
                        else:
                            self.configure(width=390, height=350, border_width=0, scrollbar_button_color='#696969')
                            obj.grid_remove()

                    def sort(self, z_a: bool = False):
                        addition = False  # If the user is in the process of adding a new service
                        if not self.service_objects[-1].name:  # Last list item name is None (not added yet)
                            addition = self.service_objects[-1]
                            self.service_objects.pop(-1)
                        self.service_objects = [o for o in sorted(self.service_objects, reverse=z_a,
                                                                  key=lambda o: o.name)]
                        for i, o in enumerate(self.service_objects, 1 if addition else 0):
                            o.grid_configure(row=i), o.tkraise()  # raise ensures proper TAB order
                            # grid_configure places it again, so remove it if it is supposed to be unmapped
                            # (does not match the current search query)
                            if not o.name.lower().startswith(search.query.get().strip().lower()):
                                o.grid_remove()
                        if addition:  # Re-add the addition service box
                            self.service_objects.append(addition)

                    def query(self, q: str = ''):
                        n = 0
                        for o in self.service_objects:
                            if o.name.lower().startswith(q.strip().lower()):  # If the object name starts with the query
                                o.grid()
                                n += 1
                            else:  # Else remove it (keeps grid configuration)
                                o.grid_remove()
                        self.special_message(self.no_results, not n, '#ff3333')  # No results message

                    def add(self):
                        if not self.adding:
                            if not len(manager.get_services()):  # Only do it once - remove no services
                                self.special_message(self.no_services, False)
                            else:
                                search.query.delete(0, 'end')  # Clear search query
                                self.query()  # Re-update results
                            # --
                            self.adding = True
                            (new := self.Service(self, {})).grid(row=0, column=0, pady=(0, 5)), new.label.focus_set()
                            for i, o in enumerate(self.service_objects, 1):
                                o.grid_configure(row=i)
                            self.service_objects.append(new)

                class Search(ctk.CTkFrame):  # Searchbar
                    def state_check(self, s: dict = None):
                        # s can be provided as to reduce calls to get_services()
                        self.query.configure(
                            state='normal' if (enable := len(s if s else manager.get_services()) > 1) else 'disabled')
                        if not enable:
                            self.focus_set()  # Otherwise <KeyRelease> can still be called

                    def __init__(self, _master):
                        super().__init__(_master, 185, 35, 5, 2, fg_color='transparent',
                                         border_color='#000000')
                        # Search icon
                        img = ctk.CTkLabel(self, 35, 35, 0, fg_color='#000000', bg_color=TRANS,
                                           text='', compound='left',
                                           image=ctk.CTkImage(Image.open(f'{PATH}search.png'), size=(20, 20)))
                        set_opacity(img, color=TRANS), img.place(x=2, y=0)  # Remove BG and place
                        # Entry box for query
                        self.query = ctk.CTkEntry(self, 147, 30, 0, 0, fg_color='transparent', text_color='#212121',
                                                  font=(JB, 18), validate='key', validatecommand=
                                                  (self.register(lambda t: len(t) <= MAX_SERVICE_LENGTH), '%P'),
                                                  placeholder_text_color='#919191', placeholder_text='Search')
                        self.query.bind('<KeyRelease>', lambda _: services.query(self.query.get()))
                        self.state_check(), ctrl_backspace_bind(self.query), self.query.place(x=35, y=2)

                class AddService(ctk.CTkFrame):
                    def __init__(self, _master):
                        # Label and button with the text being '+' doesn't work as the plus exceeds the 35x35px
                        # dimensions. Because of this, a frame with the image on top is used, which means the frame
                        # and label img both need mouse bindings
                        super().__init__(_master, 35, 35, 12, fg_color='#55BB33', cursor='hand2')
                        self.grid_propagate(False), self.grid_anchor('center')
                        plus = ctk.CTkLabel(self, text='+', text_color='#FFFFFF', font=(JBB, 32), fg_color=TRANS,
                                            bg_color=TRANS)
                        set_opacity(plus, color=TRANS), plus.grid(padx=(0, 1), pady=(0, 2))
                        for o in {self, plus}:
                            # Hover colours
                            o.bind('<Enter>', lambda _: self.configure(fg_color='#5BCA37'))  # Hover over
                            o.bind('<Leave>', lambda _: self.configure(fg_color='#55BB33'))  # Exit
                            o.bind('<Button-1>', lambda _: services.add())
                # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                super().__init__(master), self.grid_propagate(False), self.grid_anchor('n')
                ctk.CTkLabel(self, text='Your services', text_color='#000000', font=(JB, 24)).grid(
                    row=0, column=0, columnspan=3, sticky='w', pady=(30, 2))  # Services header text
                #
                # ░░░░░░░░░░░░░░░░░░░
                # SECOND ROW BUTTONS
                (search := Search(self)).grid(row=1, column=0, sticky='w', padx=(0, 100))
                (sorting := ctk.CTkButton(
                    self, 75, 35, 5, 2, fg_color='transparent', border_color='#000000', hover_color='#FFFFFF',
                    text='A-Z', text_color='#000000', font=(JBB, 20),
                    image=ctk.CTkImage(Image.open(f'{PATH}sort.png'), size=(12, 10)),
                    command=lambda: (
                        sorting.configure(text=(order := 'A-Z' if sorting.cget('text') == 'Z-A' else 'Z-A')),
                        services.sort(order != 'A-Z')
                    ))).grid(row=1, column=1, sticky='e')  # Sorting A-Z, Z-A
                AddService(self).grid(row=1, column=2, sticky='e')  # Add account button
                # ░░░░░░░░░░░░░░░░░░░
                (services := Services(self)).grid(row=2, column=0, columnspan=3, pady=(10, 0))
                # Change Password footer button
                ctk.CTkButton(self, GUI.WIDTH, 40, 0, text='Change the master password', font=(JB, 12),
                              text_color='#343434', fg_color='#E4E3E3', hover_color='#d8d8d8',
                              # provide this MainScreen instance, so it can return to the same one upon change
                              command=lambda: switch_screen(LoginScreen(master, True, self), True),
                              image=ctk.CTkImage(Image.open(f'{PATH}edit.png'), size=(16, 16))
                              ).place(x=0, y=GUI.HEIGHT - 80)
                # For mouse_off binding
                self.mb = Services.Service, Services.Service.Account, services, sorting

        class LoginScreen(self.Screen):
            class Content(ctk.CTkFrame):  # Separate frame to keep it vertically centered
                # noinspection PyMethodParameters
                # self is _self here so switch_screen() can access parent CTk
                def __init__(_self, master, new: bool, change: MainScreen = None):
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
                            _self.password.configure(border_color='#ff3333')
                            _self.button.configure(fg_color='#ff3333', state='disabled')

                        if len(entry := _self.password.get()) < MIN_PASS_LENGTH:
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
                        if len(_self.password.get()) > 0 and validate(1, e.char):
                            _self.password.configure(border_color='#B8B7B7')
                            _self.button.configure(fg_color='#55BB33', state='normal')
                    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                    super().__init__(master, fg_color='transparent')
                    label = ctk.CTkLabel(_self, text=f"{'Change' if change else 'Create' if new else 'Enter'} "
                                                     f"your password", font=(JB, 16), text_color='#000000',
                                         fg_color=TRANS)
                    set_opacity(label, color=TRANS), label.grid(row=0, column=0, sticky='w')
                    # Password Entry
                    _self.password = ctk.CTkEntry(_self, 300, 80, 0, 2, 'transparent', '#E4E4E4', '#B8B7B7',
                                                     '#000000', font=(JB, 28), show='*', validate='key',
                                                  validatecommand=(_self.register(validate), '%d', '%P'))
                    _self.password.bind('<Control-KeyPress-BackSpace>', lambda e: (reset(e),
                                                                                   _self.password.delete(0, 'end')))
                    _self.password.bind('<KeyRelease-Return>', check_password)
                    _self.password.bind('<KeyRelease>', reset)
                    _self.password.bind('<Tab>', lambda _: 'break')  # Disables TAB within password entry
                    _self.button = ctk.CTkButton(_self, 50, 80, 0, fg_color='#55BB33', text='',
                                                 hover_color='#5BCA37', command=check_password,
                                                 image=ctk.CTkImage(Image.open(
                                                      f'{PATH}{"edit" if change else "chev_right"}.png'),
                                                      size=(22, 22) if change else (42, 42)))
                    # --
                    Visibility(_self, _self.password, width=50, anchor='center').grid(
                        row=0, column=1, sticky='e')
                    _self.password.grid(row=1, column=0), _self.button.grid(row=1, column=1)

            def __init__(self, master, new: bool, change: MainScreen = None):
                super().__init__(master), self.grid_propagate(False), self.grid_anchor('center')
                self.change = change  # Class attribute so inactivity timer can determine change status
                # Stripes background
                ctk.CTkLabel(self, text='', image=ctk.CTkImage(Image.open(f'{PATH}stripes.png'),
                                                               size=(GUI.WIDTH, GUI.HEIGHT))).pack()
                self.footer.tkraise()  # Footer above stripes background image
                # Place content + set focus after 75ms to password entry box
                (c := self.Content(self, new, change)).grid(pady=(0, 106)), self.after(75, c.password.focus_set)
                # ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
                placement = (45, 363)  # Default X/Y for Caps Lock
                if change:  # Back button
                    back = ctk.CTkButton(self, 32, 32, 0, text='', fg_color=TRANS,
                                         hover_color=TRANS, command=lambda: switch_screen(change))
                    img_button_brightness(back, Image.open(f'{PATH}back_arrow.png'), (32, 32), 1.3)
                    set_opacity(back, color=TRANS), back.place(x=45, y=45)
                if new:  # Label for first time startup warning user to remember password
                    length = ctk.CTkLabel(self, text=f'The password must be between {MIN_PASS_LENGTH} and '
                                                     f'{MAX_PASS_LENGTH} characters.', font=(JB, 12),
                                          text_color='#000000', fg_color=TRANS)
                    warning = ctk.CTkLabel(self, text="WARNING: Your password cannot be reset if you forget it. This "
                                                      "could lead to permanent data loss! Ensure you keep record of "
                                                      "your password.", font=(JB, 12), wraplength=350,
                                           justify='left', fg_color=TRANS, text_color='#CC0202')
                    set_opacity(length, color=TRANS), length.place(x=50, y=290)
                    set_opacity(warning, color=TRANS), warning.place(x=50, y=315)
                else:  # Standard placement
                    placement = (45, 290)
                # ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
                try:  # Try to set up Caps Lock warning for Windows
                    from ctypes import windll
                    def listen():
                        if windll.user32.GetKeyState(0x14):  # Turned on
                            self.caps_lock.place(x=placement[0], y=placement[1])
                        else:
                            self.caps_lock.place_forget()
                        self.after(1, listen)
                    self.caps_lock = ctk.CTkLabel(self, text='Caps Lock is On', text_color='#4046b6', font=(JBB, 12),
                                                  fg_color=TRANS, compound='left', padx=5,
                                                  image=ctk.CTkImage(Image.open(f'{PATH}warning.png'), size=(18, 18)))
                    set_opacity(self.caps_lock, color=TRANS)
                    self.after(1, listen)
                except (Exception,):
                    pass

        # 〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉
        # Inactivity system for the MainScreen, so it will switch back to the login screen if there has
        # been no mouse motion, button presses or key presses for a certain period
        # (inside __init__ so it can access and change between screens)
        def inactivity_bindings():
            def r():  # Destroy reset + interrupt timer wrapper
                self.timer = 0
            self.bind_all('<Motion>', lambda _: r(), '+')
            self.bind_all('<Button>', lambda _: r(), '+')
            self.bind_all('<KeyPress>', lambda _: r(), '+')

        # noinspection PyUnresolvedReferences
        def inactivity_timer():
            change = None
            # Only process timer if screen is MainScreen or LoginScreen for changing password
            if isinstance(self.current_screen, MainScreen) or (change := self.current_screen.change):
                if -1 < self.timer < INACTIVITY_PERIOD:
                    self.timer += 1
                elif self.timer == INACTIVITY_PERIOD:  # Execute timeout function
                    self.timer = -1  # Stop timer
                    self.manager.write()  # Save Manager data
                    del self.manager  # Remove manager instance
                    if change:  # If in the LoginScreen for changing password, delete the preserved MainScreen
                        change.destroy()
                    switch_screen(LoginScreen(self, False))
            self.after(1000, inactivity_timer)

        # 〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉〉
        # For handling Service and Account entry editing
        def recursive(i, obj):
            # noinspection PyUnresolvedReferences
            if isinstance(obj, i):
                return obj
            elif obj != self:
                return recursive(i, obj.master)
            else:
                return

        def instance(i, obj: tuple) -> int:
            if isinstance(i, obj[0]):
                return 1
            elif isinstance(i, obj[1]):
                return 2
            else:
                return 0

        def mouse_off(e):
            if isinstance(self.current_screen, MainScreen):  # Only MainScreen
                # Unpack to Service, Account, Services() instance, sorting btn
                ser, acc, ser_obj, sort = self.current_screen.mb
                try:
                    if ser_obj.double:  # Allow double mouse click for setting service entry focus
                        ser_obj.double = False
                    # If the current focus is a Service, and the clicked widget is not the focus
                    elif ((i := instance((parent := (f := self.focus_get()).master.master), (ser, acc)))
                          and e.widget != f):
                        args = []
                        if i == 1:  # Service
                            if not parent.name:  # Currently adding service
                                # [parent == recursive(ser, e.widget)] =
                                #   Allow clicking within Service addition
                                # [e.widget.master == sort] Allow clicking A-Z sorting
                                # ['addservice' in str(e.widget)] Make clicking the Add button do nothing
                                if (parent == recursive(ser, e.widget) or e.widget.master == sort or
                                        'addservice' in str(e.widget)):
                                    return
                        else:  # Account
                            args = [f.master]
                            # Clicking within account when adding or add acc button
                            if not parent.username and (parent == recursive(acc, e.widget)
                                                        or 'addaccount' in str(e.widget)):
                                return
                        # Change focus if the widget is not AddService or AddAccount obj (so adding can take focus)
                        parent.handle_change(not any(x in str(e.widget) for x in {'addservice', 'addaccount'}), *args)
                except AttributeError:  # Is not Service
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
        # --
        self.timer = 0
        inactivity_bindings(), inactivity_timer()
        self.bind('<Button-1>', mouse_off, '+')  # For editing Services & Accounts
        self.mainloop()


if __name__ == '__main__':
    GUI()
