import sys
from PyQt6.QtWidgets import *
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6 import QtCore
from crypto import Ui_MainWindow
from login import Ui_Form
from browser import Ui_MainWindow as Ui_Browser
from crypto_func import *
import config


class Auth(QWidget):
    """ Окно авторизации """
    def __init__(self):
        """ Функция инициализирует элементы окна авторизации """
        super(Auth, self).__init__()
        self.auth = Ui_Form()
        self.auth.setupUi(self)
        # Основные обработчики
        self.validate_flag = False
        self.auth.pushButton.clicked.connect(self.check_passwd)
        self.auth.checkBox.clicked.connect(self.visibility)
        # Добавление обработчика нажатия Enter на клавиатуре
        self.auth.lineEdit_2.returnPressed.connect(self.check_passwd)

    def visibility(self):
        """ Функция отображает пароль при нажатии на чекбокс """
        if self.auth.lineEdit_2.echoMode() == QLineEdit.EchoMode.Normal:
            self.auth.lineEdit_2.setEchoMode(QLineEdit.EchoMode.Password)
        else:
            self.auth.lineEdit_2.setEchoMode(QLineEdit.EchoMode.Normal)

    def check_passwd(self):
        """ Функция проверяет логин/пароль и осуществляет авторизацию """
        user = self.auth.lineEdit.text()
        passwd = self.auth.lineEdit_2.text()
        if len(user) > 0 and len(passwd) > 0:
            # Вычисление хэша пароля
            hash_passwd = hashlib.md5(passwd.encode().strip()).hexdigest()
            # Проверка логина и хэша пароля
            if user == config.user and hash_passwd == config.password:
                self.validate_flag = True
                self.close()
                # Открытие основного окна
                window.show()

    def closeEvent(self, value, **kwargs):
        """ Функция закрывает программу в случае закрытия окна авторизации """
        if not self.validate_flag:
            raise SystemExit


class Application(QMainWindow):
    """ Основное окно приложения """
    def __init__(self):
        """ Функция инициализирует элементы окна приложения """
        super(Application, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        # Обработчики выбора кодировки/шифра
        self.ui.comboBox.currentTextChanged.connect(self.choice_crypto)
        # Обработчики кнопок
        self.ui.button_decrypt.clicked.connect(self.checked_decrypt)
        self.ui.button_encrypt.clicked.connect(self.checked_encrypt)
        self.ui.button_chef.clicked.connect(self.checked_browser)
        # Обработчики меню-бара
        self.ui.action_open.triggered.connect(self.open)
        self.ui.action_save.triggered.connect(self.save)
        self.ui.action_theme.triggered.connect(self.color_theme)
        # Текущая тема
        self.white_theme = True
        # Подсказки
        self.ui.button_decrypt.setToolTip("Декодировать")
        self.ui.button_encrypt.setToolTip("Закодировать/зашифровать")
        self.ui.button_chef.setToolTip("Открыть браузер")

    def choice_crypto(self):
        """ Функция обрабатывает действия при выборе кодировки/шифра """
        self.ui.button_encrypt.setChecked(False)
        self.ui.button_decrypt.setChecked(False)
        self.ui.textEdit_2.clear()
        # Отключение кнопки Decrypt при выборе алгоритма шифрования
        if self.ui.comboBox.currentText() in ('MD5', 'SHA1', 'SHA256', 'SHA512'):
            self.ui.button_decrypt.setEnabled(False)
        else:
            self.ui.button_decrypt.setEnabled(True)

    def checked_decrypt(self):
        """ Функция обрабатывает нажатие на кнопку Decrypt """
        self.ui.button_encrypt.setChecked(False)
        choice_method = self.ui.comboBox.currentText()
        try:
            self.decrypting()
        except Exception:
            QMessageBox.about(self, "Информация",
                              f"Введенный текст невозможно декодировать!\n"
                              f"Он не относится к алгоритму {choice_method}")
        # Действия в случае изменения текста
        self.ui.textEdit.textChanged.connect(self.clear)

    def decrypting(self):
        """ Функция декодирует текст """
        choice_method = self.ui.comboBox.currentText()
        plain_text = self.ui.textEdit.toPlainText()
        if choice_method == 'Base64':
            self.ui.textEdit_2.setText(base64_func(plain_text))
        elif choice_method == 'Base32':
            self.ui.textEdit_2.setText(base32_func(plain_text))
        elif choice_method == 'HEX':
            self.ui.textEdit_2.setText(hex_func(plain_text))
        elif choice_method == 'URL':
            self.ui.textEdit_2.setText(url_func(plain_text))
        elif choice_method == 'ROT13':
            self.ui.textEdit_2.setText(rot13_func(plain_text))

    def checked_encrypt(self):
        """ Функция обрабатывает нажатие на кнопку Encrypt """
        self.ui.button_decrypt.setChecked(False)
        self.encrypting()
        # Действия в случае изменения текста
        self.ui.textEdit.textChanged.connect(self.clear)

    def encrypting(self):
        """ Функция кодирует/шифрует текст """
        choice_method = self.ui.comboBox.currentText()
        plain_text = self.ui.textEdit.toPlainText()
        if choice_method == 'Base64':
            self.ui.textEdit_2.setText(base64_func(plain_text, True))
        elif choice_method == 'Base32':
            self.ui.textEdit_2.setText(base32_func(plain_text, True))
        elif choice_method == 'HEX':
            self.ui.textEdit_2.setText(hex_func(plain_text, True))
        elif choice_method == 'URL':
            self.ui.textEdit_2.setText(url_func(plain_text, True))
        elif choice_method == 'ROT13':
            self.ui.textEdit_2.setText(rot13_func(plain_text, True))
        elif choice_method == 'MD5':
            self.ui.textEdit_2.setText(md5_func(plain_text))
        elif choice_method == 'SHA1':
            self.ui.textEdit_2.setText(sha1_func(plain_text))
        elif choice_method == 'SHA256':
            self.ui.textEdit_2.setText(sha256_func(plain_text))
        elif choice_method == 'SHA512':
            self.ui.textEdit_2.setText(sha512_func(plain_text))

    def clear(self):
        """ Функция очищает результат и возвращает состояние кнопок """
        self.ui.textEdit_2.clear()
        self.ui.button_encrypt.setChecked(False)
        self.ui.button_decrypt.setChecked(False)

    def checked_browser(self):
        browser.show()

    def open(self):
        """ Функция добавляет информацию из файла в окно ввода """
        path = QFileDialog.getOpenFileNames(self, "Открыть файл", "", "Document *.txt")
        # Проверка на то, был ли выбран файл
        if path[0]:
            # Чтение информации из файла и добавление ее в окно ввода
            with open(path[0][0], "r") as file:
                file_text = file.read()
            self.ui.textEdit.setText(file_text)
            # Вывод информации в статус-бар
            self.ui.statusBar.showMessage("Информация из файла загружена")
        else:
            self.ui.statusBar.showMessage("Файл для чтения не выбран")

    def save(self):
        """ Функция сохраняет результат в файл """
        path = QFileDialog.getSaveFileName(self, "Сохранить файл", "", "Document *.txt")
        # Проверка на то, был ли выбран файл
        if path[0]:
            # Запись информации в файл
            with open(path[0], "w") as file:
                file.write(self.ui.textEdit_2.toPlainText())
            # Вывод информации в статус-бар
            self.ui.statusBar.showMessage("Результат сохранен в файл")
        else:
            self.ui.statusBar.showMessage("Файл для записи не выбран")

    def color_theme(self):
        """ Функция меняет тему приложения """
        default_style = """
            QMainWindow {}
            """
        style = """
            QMainWindow {background-color: #535353}
            QPushButton {background-color: #878787}
            QTextEdit {background-color: #878787}
            QTextEdit:hover {border-color: white}
            """
        if self.white_theme:
            self.white_theme = False
            self.setStyleSheet(style)
        else:
            self.white_theme = True
            self.setStyleSheet(default_style)

    def closeEvent(self, value):
        """ Функция вызывает уведомление при попытке закрыть приложение """
        result = QMessageBox.question(self, "Внимание", "Закрыть программу?")
        if result == QMessageBox.StandardButton.No:
            value.ignore()


class Browser(QMainWindow):
    """ Окно браузера """
    def __init__(self):
        """ Функция инициализирует элементы окна приложения """
        super(Browser, self).__init__()
        self.br = Ui_Browser()
        self.br.setupUi(self)
        # Инициализация WebView
        self.web = QWebEngineView()
        self.br.gridLayout.addWidget(self.web, 1, 0, 1, 9)
        # Основные обработчики
        self.br.toolButton.clicked.connect(self.web.back)
        self.br.toolButton_2.clicked.connect(self.web.reload)
        self.br.toolButton_3.clicked.connect(self.search)
        self.br.toolButton_4.clicked.connect(self.home)
        # Добавление обработчика нажатия Enter на клавиатуре
        self.br.lineEdit.returnPressed.connect(self.search)
        # Подсказки
        self.br.toolButton.setToolTip('Назад')
        self.br.toolButton_2.setToolTip('Обновить')
        self.br.toolButton_3.setToolTip('Поиск')
        self.br.toolButton_4.setToolTip('Главная')

    def home(self):
        """ Функция отображает домашнюю страницу """
        home_page = QtCore.QUrl('https://duckduckgo.com')
        self.web.load(home_page)

    def search(self):
        """ Функция осуществляет поиск информации """
        text = self.br.lineEdit.text()
        if len(text) > 0:
            if not text.startswith('http'):
                text = QtCore.QUrl('https://duckduckgo.com/?q=' + text)
            else:
                text = QtCore.QUrl(text)
            self.web.load(text)


if __name__ == "__main__":
    # Создание объектов приложения
    app = QApplication(sys.argv)
    window = Application()
    login = Auth()
    browser = Browser()
    # Отображение окна авторизации
    login.show()
    # Выход из приложения при закрытии окна
    sys.exit(app.exec())