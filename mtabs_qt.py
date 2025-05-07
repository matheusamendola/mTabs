from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QAction, QDialog, QFormLayout, QLineEdit, QComboBox, QPushButton, QMessageBox, QLabel, QSizePolicy
from PyQt5.QtCore import Qt
from PyQt5.QAxContainer import QAxWidget
import sys
import os
from cryptography.fernet import Fernet
from functools import partial

FAVORITES_FILE = 'favoritos.dat'
FAVORITES_KEY_FILE = 'favoritos.key'

def generate_key():
    """
    Gera e salva uma chave de criptografia para os favoritos, se não existir.
    Não recebe parâmetros e não retorna nada.
    """
    if not os.path.exists(FAVORITES_KEY_FILE):
        key = Fernet.generate_key()
        with open(FAVORITES_KEY_FILE, 'wb') as f:
            f.write(key)

def load_key():
    """
    Carrega a chave de criptografia dos favoritos do arquivo.
    Retorna:
        bytes: chave carregada.
    """
    with open(FAVORITES_KEY_FILE, 'rb') as f:
        return f.read()

def save_favorites_encrypted(favorites):
    """
    Salva os favoritos em arquivo criptografado.
    Parâmetros:
        favorites (dict): dicionário de favoritos.
    Não retorna nada.
    """
    import pickle
    key = load_key()
    fernet = Fernet(key)
    data = pickle.dumps(favorites)
    encrypted = fernet.encrypt(data)
    with open(FAVORITES_FILE, 'wb') as f:
        f.write(encrypted)

def load_favorites_encrypted():
    """
    Carrega os favoritos de um arquivo criptografado.
    Retorna:
        dict: dicionário de favoritos, ou {} se não existir.
    """
    import pickle
    if not os.path.exists(FAVORITES_FILE) or not os.path.exists(FAVORITES_KEY_FILE):
        return {}
    key = load_key()
    fernet = Fernet(key)
    with open(FAVORITES_FILE, 'rb') as f:
        encrypted = f.read()
    data = fernet.decrypt(encrypted)
    return pickle.loads(data)

class RDPWidget(QWidget):
    """
    Widget que embute o ActiveX do cliente RDP do Windows (MsTscAx.dll) usando QAxWidget.
    Parâmetros:
        host (str): endereço do host remoto.
        username (str): nome de usuário.
        password (str): senha.
        domain (str): domínio.
        port (int): porta do RDP.
        nla (bool): True para NLA, False para Legacy.
    """
    def _get_initial_size(self):
        """
        Retorna o tamanho inicial do widget para ser usado como resolução da sessão RDP.
        Retorna:
            tuple: (width, height) inteiros.
        """
        width = self.width() if self.width() > 0 else 900
        height = self.height() if self.height() > 0 else 600
        return width, height

    def __init__(self, host, username, password, domain='', port=3389, nla=True, parent=None):
        """
        Inicializa o widget de conexão RDP usando o ActiveX do Windows.
        Parâmetros:
            host (str): endereço do host remoto.
            username (str): nome de usuário.
            password (str): senha.
            domain (str): domínio.
            port (int): porta do RDP.
            nla (bool): True para NLA, False para Legacy.
            parent: widget pai (opcional).
        Não retorna nada.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.rdp = QAxWidget('MsTscAx.MsTscAx.7')
        self.rdp.exception.connect(self.handle_ax_exception)
        self.rdp.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.rdp)
        layout.setAlignment(self.rdp, Qt.AlignTop | Qt.AlignLeft)
        self.setLayout(layout)
        # Não conecta nem define resolução aqui, faz isso no showEvent
        self._rdp_config = {
            'host': host,
            'username': username,
            'password': password,
            'domain': domain,
            'port': port,
            'nla': nla
        }

    def showEvent(self, event):
        """
        Evento chamado quando o widget é exibido pela primeira vez.
        Ajusta a resolução do RDP para o tamanho real do QAxWidget e conecta.
        Parâmetros:
            event (QShowEvent): evento de exibição.
        Não retorna nada.
        """
        super().showEvent(event)
        width = self.rdp.width() if self.rdp.width() > 0 else 900
        height = self.rdp.height() if self.rdp.height() > 0 else 600
        print(f"Resolução inicial do QAxWidget para o RDP (showEvent): {width}x{height}")
        self.rdp.setProperty('Server', self._rdp_config['host'])
        self.rdp.setProperty('UserName', self._rdp_config['username'])
        if self._rdp_config['domain']:
            self.rdp.setProperty('Domain', self._rdp_config['domain'])
        self.rdp.setProperty('DesktopWidth', width)
        self.rdp.setProperty('DesktopHeight', height)
        adv = self.rdp.querySubObject("AdvancedSettings")
        if adv:
            adv.setProperty("ClearTextPassword", self._rdp_config['password'])
            adv.setProperty("AuthenticationLevel", 2 if self._rdp_config['nla'] else 0)
            if self._rdp_config['port'] != 3389:
                adv.setProperty("RDPPort", self._rdp_config['port'])
            adv.setProperty("DisplayConnectionBar", True)
            adv.setProperty("DesktopWidth", width)
            adv.setProperty("DesktopHeight", height)
        self.rdp.dynamicCall('Connect()')

    def _ajustar_resolucao_e_conectar(self):
        """
        Ajusta a resolução do RDP para o tamanho atual do QAxWidget e conecta.
        Não recebe parâmetros e não retorna nada.
        """
        width = self.rdp.width() if self.rdp.width() > 0 else 900
        height = self.rdp.height() if self.rdp.height() > 0 else 600
        print(f"Resolução inicial do QAxWidget para o RDP: {width}x{height}")
        self.rdp.setProperty('DesktopWidth', width)
        self.rdp.setProperty('DesktopHeight', height)
        adv = self.rdp.querySubObject("AdvancedSettings")
        if adv:
            adv.setProperty("DesktopWidth", width)
            adv.setProperty("DesktopHeight", height)
        self.rdp.dynamicCall('Connect()')

    def resizeEvent(self, event):
        """
        Evento chamado quando o widget é redimensionado.
        Imprime o tamanho atual do QAxWidget e ajusta o tamanho visual do controle.
        Parâmetros:
            event (QResizeEvent): evento de redimensionamento.
        Não retorna nada.
        """
        super().resizeEvent(event)
        width = self.width()
        height = self.height()
        self.rdp.resize(width, height)
        print(f"Tamanho atual do QAxWidget (RDP): {self.rdp.width()}x{self.rdp.height()}")
        # Não altera resolução do RDP após conexão

    def handle_ax_exception(self, code, source, desc, help):
        """
        Slot para tratar exceções do QAxWidget.
        Parâmetros:
            code (int): código do erro.
            source (str): fonte do erro.
            desc (str): descrição do erro.
            help (str): ajuda adicional.
        Não retorna nada.
        """
        print(f"Exceção QAxWidget: code={code}, source={source}, desc={desc}, help={help}")

class ConnectionDialog(QDialog):
    """
    Diálogo para entrada dos dados de conexão RDP.
    """
    def __init__(self, parent=None):
        """
        Inicializa o diálogo de conexão.
        Parâmetros:
            parent: widget pai (opcional).
        Não retorna nada.
        """
        super().__init__(parent)
        self.setWindowTitle('Nova Conexão RDP')
        layout = QFormLayout(self)
        self.host_input = QLineEdit()
        self.user_input = QLineEdit()
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.Password)
        self.domain_input = QLineEdit()
        self.port_input = QLineEdit()
        self.port_input.setText('3389')
        self.nla_combo = QComboBox()
        self.nla_combo.addItems(['NLA (Recomendado)', 'Legacy (Sem NLA)'])
        layout.addRow('Host:', self.host_input)
        layout.addRow('Usuário:', self.user_input)
        layout.addRow('Senha:', self.pass_input)
        layout.addRow('Domínio:', self.domain_input)
        layout.addRow('Porta:', self.port_input)
        layout.addRow('Autenticação:', self.nla_combo)
        # Campos para favoritar
        self.fav_name_input = QLineEdit()
        self.fav_folder_input = QLineEdit()
        self.fav_btn = QPushButton('Favoritar')
        self.fav_btn.clicked.connect(self._on_fav_clicked)
        layout.addRow('Nome do favorito:', self.fav_name_input)
        layout.addRow('Pasta (opcional):', self.fav_folder_input)
        layout.addRow(self.fav_btn)
        btn_ok = QPushButton('OK')
        btn_ok.clicked.connect(self.accept)
        layout.addRow(btn_ok)
        self._fav_data = None

    def _on_fav_clicked(self):
        """
        Salva os dados atuais do formulário como favorito (nome e pasta personalizados) e fecha o diálogo sem abrir a conexão.
        Não recebe parâmetros e não retorna nada.
        """
        name = self.fav_name_input.text().strip()
        folder = self.fav_folder_input.text().strip()
        if not name:
            QMessageBox.warning(self, 'Favoritos', 'Informe um nome para o favorito.')
            return
        host = self.host_input.text().strip()
        username = self.user_input.text().strip()
        password = self.pass_input.text()
        domain = self.domain_input.text().strip()
        try:
            port = int(self.port_input.text())
        except ValueError:
            port = 3389
        nla = self.nla_combo.currentIndex() == 0
        self._fav_data = (name, folder, {
            'host': host,
            'username': username,
            'password': password,
            'domain': domain,
            'port': port,
            'nla': nla
        })
        # Fecha o diálogo sem aceitar (não chama accept), apenas salva o favorito
        self.done(0)

    def get_favorite_data(self):
        """
        Retorna os dados do favorito, se o usuário clicou em Favoritar.
        :return: tuple (name, folder, conn_data) ou None
        """
        return self._fav_data

    def get_data(self):
        """
        Retorna os dados inseridos pelo usuário.
        :return: tuple (host, username, password, domain, port, nla)
        """
        host = self.host_input.text().strip()
        username = self.user_input.text().strip()
        password = self.pass_input.text()
        domain = self.domain_input.text().strip()
        try:
            port = int(self.port_input.text())
        except ValueError:
            port = 3389
        nla = self.nla_combo.currentIndex() == 0
        return (host, username, password, domain, port, nla)

class MTabsMainWindow(QMainWindow):
    """
    Janela principal do aplicativo, gerencia as abas de conexões RDP.
    """
    def __init__(self):
        """
        Inicializa a janela principal e o QTabWidget.
        Inicializa também a estrutura de favoritos antes de criar o menu.
        Carrega favoritos do arquivo criptografado.
        """
        super().__init__()
        self.setWindowTitle('mTabs (Qt) - Gerenciador de Conexões RDP')
        self.resize(900, 600)
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setStyleSheet("""
            QTabBar::tab {
                height: 20px;
            }
            QTabBar::tab:selected {
                height: 27px;
            }
        """)
        self.setCentralWidget(self.tab_widget)
        generate_key()
        self.favorites = load_favorites_encrypted()
        self._create_menu()
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self._show_welcome()
        self.set_minimum_size_to_current()

    def _create_menu(self):
        """
        Cria o menu principal da aplicação, incluindo o menu de debug e o menu de favoritos.
        Não recebe parâmetros e não retorna nada.
        """
        menubar = self.menuBar()
        conex_menu = menubar.addMenu('Conexão')
        add_action = QAction('Adicionar conexão', self)
        add_action.triggered.connect(self.add_connection)
        conex_menu.addAction(add_action)
        # Menu de favoritos
        self.favorites_menu = menubar.addMenu('Favoritos')
        self._update_favorites_menu()
        # Menu de debug
        debug_menu = menubar.addMenu('Debug')
        resize_action = QAction('Testar redimensionamento RDP (tamanho atual da janela)', self)
        resize_action.triggered.connect(self.test_resize_rdp_to_window)
        debug_menu.addAction(resize_action)

    def _update_favorites_menu(self):
        """
        Atualiza o menu de favoritos, criando submenus para pastas e ações para conexões salvas.
        O nome exibido será sempre o nome personalizado do favorito.
        Não recebe parâmetros e não retorna nada.
        """
        self.favorites_menu.clear()
        def add_fav_items(menu, fav_dict):
            for key, value in fav_dict.items():
                if isinstance(value, dict) and not all(k in value for k in ('host', 'username', 'password')):
                    submenu = menu.addMenu(key)
                    add_fav_items(submenu, value)
                else:
                    # Exibe apenas o nome personalizado do favorito
                    action = QAction(key, self)
                    action.triggered.connect(partial(self._open_favorite_connection, value))
                    menu.addAction(action)
        add_fav_items(self.favorites_menu, self.favorites)

    def _open_favorite_connection(self, fav_data):
        """
        Abre uma conexão RDP a partir dos dados de um favorito em uma nova aba, sem mostrar atributos ao usuário.
        Parâmetros:
            fav_data (dict): dados da conexão favorita.
        Não retorna nada.
        """
        # Conecta diretamente sem mostrar atributos
        self._add_tab(
            fav_data['host'], fav_data['username'], fav_data['password'],
            fav_data.get('domain', ''), fav_data.get('port', 3389), fav_data.get('nla', True)
        )

    def add_favorite(self, name, folder_path, conn_data):
        """
        Adiciona uma conexão aos favoritos, podendo ser dentro de uma pasta.
        Salva os favoritos criptografados após adicionar.
        Parâmetros:
            name (str): nome personalizado do favorito.
            folder_path (str): caminho da pasta (ex: 'Trabalho/Servidores').
            conn_data (dict): dados da conexão.
        Não retorna nada.
        """
        parts = [p for p in folder_path.split('/') if p]
        d = self.favorites
        for part in parts:
            if part not in d:
                d[part] = {}
            d = d[part]
        d[name] = conn_data
        self._update_favorites_menu()
        save_favorites_encrypted(self.favorites)

    def test_resize_rdp_to_window(self):
        """
        Testa o redimensionamento do widget RDP ativo para o tamanho atual da janela principal.
        Não recebe parâmetros e não retorna nada.
        """
        current_size = self.size()
        widget = self.tab_widget.currentWidget()
        if widget and hasattr(widget, 'rdp'):
            widget.setMinimumSize(current_size)
            widget.setMaximumSize(current_size)
            widget.resize(current_size)
            widget.rdp.setMinimumSize(current_size)
            widget.rdp.setMaximumSize(current_size)
            widget.rdp.resize(current_size)
            if hasattr(widget, '_set_rdp_resolution'):
                widget._set_rdp_resolution(current_size.width(), current_size.height())

    def add_connection(self):
        """
        Abre diálogo para adicionar uma nova conexão RDP.
        Não recebe parâmetros e não retorna nada.
        """
        dialog = ConnectionDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            host, username, password, domain, port, nla = dialog.get_data()
            if not host or not username:
                return
            try:
                self._add_tab(host, username, password, domain, port, nla)
                # Verifica se o usuário clicou em Favoritar
                fav_data = dialog.get_favorite_data()
                if fav_data:
                    name, folder, conn_data = fav_data
                    self.add_favorite(name, folder, conn_data)
            except Exception as e:
                QMessageBox.critical(self, 'Erro', f'Não foi possível abrir a conexão RDP: {e}')

    def _add_tab(self, host, username, password, domain, port, nla):
        """
        Adiciona uma nova aba com a conexão RDP embutida.
        O nome da aba e o título da janela exibem o nome do computador remoto.
        Parâmetros:
            host (str): endereço do host remoto.
            username (str): nome de usuário.
            password (str): senha.
            domain (str): domínio.
            port (int): porta do RDP.
            nla (bool): True para NLA, False para Legacy.
        Não retorna nada.
        """
        computer_name = self._get_computer_name_from_host(host)
        widget = RDPWidget(host, username, password, domain, port, nla)
        self.tab_widget.addTab(widget, computer_name)
        self.tab_widget.setCurrentWidget(widget)
        self.setWindowTitle(f"{computer_name} - mTabs")

    def _get_computer_name_from_host(self, host):
        """
        Obtém o nome do computador remoto a partir do endereço IP ou hostname.
        Parâmetros:
            host (str): endereço do host remoto (IP ou hostname).
        Retorna:
            str: nome do computador remoto, ou o próprio host se não for possível resolver.
        """
        import socket
        try:
            return socket.gethostbyaddr(host)[0]
        except Exception:
            return host

    def close_tab(self, index):
        """
        Fecha a aba selecionada.
        Parâmetros:
            index (int): índice da aba a ser fechada.
        """
        self.tab_widget.removeTab(index)
        if self.tab_widget.count() == 0:
            self._show_welcome()

    def _show_welcome(self):
        """
        Exibe uma mensagem amigável na tela inicial.
        """
        if self.tab_widget.count() == 0:
            welcome = QLabel("""
                <div style='text-align:center; color:#2563eb; font-size:22px; font-weight:600; margin-top:40px;'>
                Bem-vindo ao mTabs!<br><span style='color:#222;font-size:16px;font-weight:400;'>Clique em <b>Conexão → Adicionar conexão</b> para iniciar uma sessão RDP.</span>
                </div>
            """)
            welcome.setAlignment(Qt.AlignCenter)
            self.tab_widget.addTab(welcome, "Bem-vindo")

    def set_minimum_size_to_current(self):
        """
        Define o tamanho mínimo da janela principal e do widget RDP para o tamanho atual.
        Parâmetros:
            self: instância de MTabsMainWindow.
        Não retorna nada.
        """
        current_size = self.size()
        self.setMinimumSize(current_size)
        # Ajusta o tamanho mínimo do widget RDP ativo, se houver
        widget = self.tab_widget.currentWidget()
        if widget and hasattr(widget, 'setMinimumSize'):
            widget.setMinimumSize(current_size)
            # Se for um RDPWidget, também ajusta o tamanho do QAxWidget interno
            if hasattr(widget, 'rdp'):
                widget.rdp.setMinimumSize(current_size)
                # Ajusta resolução da sessão RDP
                widget.rdp.setProperty('DesktopWidth', current_size.width())
                widget.rdp.setProperty('DesktopHeight', current_size.height())

def main():
    """
    Função principal para iniciar o aplicativo mTabs (Qt).
    """
    app = QApplication(sys.argv)
    window = MTabsMainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
