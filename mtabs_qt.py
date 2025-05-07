from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QAction, QDialog, QFormLayout, QLineEdit, QComboBox, QPushButton, QMessageBox, QLabel, QSizePolicy, QTabBar, QMenu, QToolButton, QTabWidget, QHBoxLayout, QCheckBox, QColorDialog, QGridLayout
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

    def set_log_callback(self, log_callback):
        """
        Define uma função de callback para registrar logs no painel principal.
        Parâmetros:
            log_callback (callable): função que recebe (msg, level).
        Não retorna nada.
        """
        self._log_callback = log_callback

    def _log(self, msg, level="INFO"):
        """
        Chama o callback de log, se definido.
        Parâmetros:
            msg (str): mensagem a ser exibida.
            level (str): nível da mensagem (INFO, ERRO, etc).
        Não retorna nada.
        """
        if hasattr(self, '_log_callback') and self._log_callback:
            self._log_callback(msg, level)

    def showEvent(self, event):
        """
        Evento chamado quando o widget é exibido pela primeira vez.
        Ajusta a resolução do RDP para o tamanho real do QAxWidget e conecta.
        Parâmetros:
            event (QShowEvent): evento de exibição.
        Não retorna nada.
        """
        import time
        super().showEvent(event)
        start = time.time()
        self._log(f"Iniciando conexão com {self._rdp_config['host']}...", "INFO")
        width = self.rdp.width() if self.rdp.width() > 0 else 900
        height = self.rdp.height() if self.rdp.height() > 0 else 600
        try:
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
            elapsed = time.time() - start
            self._log(f"Conexão iniciada para {self._rdp_config['host']} (tempo: {elapsed:.2f}s)", "INFO")
        except Exception as e:
            self._log(f"Erro ao conectar em {self._rdp_config['host']}: {e}", "ERRO")

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
        self._log(f"Exceção QAxWidget: code={code}, source={source}, desc={desc}, help={help}", "ERRO")
        print(f"Exceção QAxWidget: code={code}, source={source}, desc={desc}, help={help}")

    def reconnect_rdp(self):
        """
        Reconecta a sessão RDP destruindo o QAxWidget antigo e criando um novo,
        garantindo que a tela branca não ocorra após reconexão.
        Não recebe parâmetros e não retorna nada.
        """
        layout = self.layout()
        if self.rdp:
            layout.removeWidget(self.rdp)
            self.rdp.deleteLater()
            self.rdp = None
        # Cria novo QAxWidget
        self.rdp = QAxWidget('MsTscAx.MsTscAx.7')
        self.rdp.exception.connect(self.handle_ax_exception)
        self.rdp.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.rdp.setStyleSheet("border: none; background: transparent;")
        layout.addWidget(self.rdp)
        layout.setAlignment(self.rdp, Qt.AlignTop | Qt.AlignLeft)
        width = self.width() if self.width() > 0 else 900
        height = self.height() if self.height() > 0 else 600
        self.rdp.resize(width, height)
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

class ClosableTabBar(QTabBar):
    """
    QTabBar customizado que permite fechar abas com o botão direito do mouse.
    """
    def mousePressEvent(self, event):
        """
        Evento chamado ao pressionar o mouse sobre a barra de abas.
        Permite o comportamento padrão do QTabBar, sem fechar ou mover abas com o botão direito.
        Parâmetros:
            event (QMouseEvent): evento do mouse.
        Não retorna nada.
        """
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        """
        Evento chamado ao soltar o mouse sobre a barra de abas.
        Se for botão do meio, fecha a aba. Se for botão direito, exibe menu de contexto com opções de reconectar e fechar aba.
        Parâmetros:
            event (QMouseEvent): evento do mouse.
        Não retorna nada.
        """
        if event.button() == Qt.MiddleButton:
            index = self.tabAt(event.pos())
            if index != -1:
                self.parent().tabCloseRequested.emit(index)
        elif event.button() == Qt.RightButton:
            index = self.tabAt(event.pos())
            if index != -1:
                menu = QMenu(self)
                def close_tab():
                    """
                    Fecha a aba selecionada.
                    Não recebe parâmetros e não retorna nada.
                    """
                    self.parent().tabCloseRequested.emit(index)
                def reconnect_tab():
                    """
                    Reconecta a sessão RDP da aba selecionada, aguardando o evento de desconexão para reconectar.
                    Não recebe parâmetros e não retorna nada.
                    """
                    widget = self.parent().widget(index)
                    if hasattr(widget, 'rdp'):
                        rdp = widget.rdp
                        def do_reconnect():
                            width = rdp.width()
                            height = rdp.height()
                            rdp.setProperty('DesktopWidth', width)
                            rdp.setProperty('DesktopHeight', height)
                            adv = rdp.querySubObject("AdvancedSettings")
                            if adv:
                                adv.setProperty("DesktopWidth", width)
                                adv.setProperty("DesktopHeight", height)
                            rdp.dynamicCall('Connect()')
                            rdp.repaint()
                            rdp.update()
                            widget.repaint()
                            widget.update()
                            try:
                                rdp.OnDisconnected.disconnect(do_reconnect)
                            except Exception:
                                pass
                        if rdp.property('Connected') == 1:
                            try:
                                rdp.OnDisconnected.disconnect(do_reconnect)
                            except Exception:
                                pass
                            rdp.OnDisconnected.connect(do_reconnect)
                            rdp.dynamicCall('Disconnect()')
                        else:
                            do_reconnect()
                menu.addAction('Reconectar', reconnect_tab)
                menu.addAction('Fechar aba', close_tab)
                menu.exec_(event.globalPos())
        else:
            super().mouseReleaseEvent(event)

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
        self.tab_widget.setTabBar(ClosableTabBar(self.tab_widget))
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setMovable(True)  # Permite arrastar as abas
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
        self.tab_widget.currentChanged.connect(self._update_window_title)
        self._show_welcome()
        self.set_minimum_size_to_current()

    def _update_window_title(self, index):
        """
        Atualiza o título da janela para refletir o nome da aba ativa.
        Parâmetros:
            index (int): índice da aba ativa.
        Não retorna nada.
        """
        if index == -1:
            self.setWindowTitle('mTabs')
        else:
            tab_text = self.tab_widget.tabText(index)
            self.setWindowTitle(f"{tab_text} - mTabs")

    def _create_menu(self):
        """
        Cria o menu principal da aplicação, incluindo o menu de debug e o menu de favoritos.
        Não recebe parâmetros e não retorna nada.
        """
        menubar = self.menuBar()
        menubar.setStyleSheet("""
            QMenuBar { background: #f0f0f0; }
            QMenuBar::item { background: transparent; color: #222; }
            QMenuBar::item:selected { background: #b3d7f3; color: #111; border: 0.5px solid #0078d7; }
            QMenu {
                background: #f5f5f5;
                color: #222;
                border: 1px solid #aaa;
            }
            QMenu::item {
                background: transparent;
                color: #222;
            }
            QMenu::item:selected {
                background: #b3d7f3;
                color: #111;
                border: 0.5px solid #0078d7;
            }
        """)
        conex_menu = menubar.addMenu('Conexão')
        add_action = QAction('Adicionar conexão', self)
        add_action.triggered.connect(self.add_connection)
        conex_menu.addAction(add_action)
        # Menu de favoritos
        self.favorites_menu = menubar.addMenu('Favoritos')
        self._update_favorites_menu()
        # Menu de debug removido

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
        computer_name = self._get_computer_name_from_host(fav_data['host'])
        widget = RDPWidget(
            fav_data['host'], fav_data['username'], fav_data['password'],
            fav_data.get('domain', ''), fav_data.get('port', 3389), fav_data.get('nla', True)
        )
        # Sempre adiciona a nova aba na última posição
        self.tab_widget.addTab(widget, computer_name)
        self.tab_widget.setCurrentWidget(widget)
        self.setWindowTitle(f"{computer_name} - mTabs")

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

    def add_connection(self):
        """
        Abre uma nova aba com o formulário de nova conexão RDP (NovaConexaoWidget).
        Não recebe parâmetros e não retorna nada.
        """
        nova_conexao = NovaConexaoWidget(on_connect=self._on_nova_conexao_connect, on_favoritar=self._on_nova_conexao_favoritar)
        self.tab_widget.addTab(nova_conexao, "Nova Conexão")
        self.tab_widget.setCurrentWidget(nova_conexao)

    def _on_nova_conexao_connect(self, data):
        """
        Callback para conectar a partir do formulário de nova conexão.
        Parâmetros:
            data (tuple): dados da conexão (host, username, password, domain, port, nla).
        Não retorna nada.
        """
        host, username, password, domain, port, nla = data
        if not host or not username:
            return
        self._add_tab(host, username, password, domain, port, nla)
        # Remove a aba de nova conexão após conectar
        idx = self.tab_widget.currentIndex()
        self.tab_widget.removeTab(idx)

    def _on_nova_conexao_favoritar(self, fav_data):
        """
        Callback para favoritar a partir do formulário de nova conexão.
        Parâmetros:
            fav_data (tuple): (name, folder, conn_data)
        Não retorna nada.
        """
        name, folder, conn_data = fav_data
        if name:
            self.add_favorite(name, folder, conn_data)

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

    def _get_computer_name_from_host(self, host, timeout=2.0):
        """
        Retorna o próprio host informado, sem tentar resolver DNS.
        Parâmetros:
            host (str): endereço do host remoto (IP ou hostname).
            timeout (float): ignorado, mantido para compatibilidade.
        Retorna:
            str: o próprio host informado.
        """
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
        Exibe o formulário de Nova Conexão como aba inicial.
        """
        if self.tab_widget.count() == 0:
            def on_connect(data):
                host, username, password, domain, port, nla = data
                if not host or not username:
                    return
                self._add_tab(host, username, password, domain, port, nla)
                self.tab_widget.removeTab(0)  # Remove a aba de nova conexão
            def on_favoritar(fav_data):
                name, folder, conn_data = fav_data
                if name:
                    self.add_favorite(name, folder, conn_data)
            nova_conexao = NovaConexaoWidget(on_connect=on_connect, on_favoritar=on_favoritar)
            self.tab_widget.addTab(nova_conexao, "Nova Conexão")
            self.tab_widget.setCurrentWidget(nova_conexao)

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

class NovaConexaoWidget(QWidget):
    """
    Widget de formulário para criar uma nova conexão RDP, exibido dentro de uma aba, com layout moderno e apenas a aba Logon.
    """
    def __init__(self, parent=None, on_connect=None, on_favoritar=None, on_close_tab=None):
        """
        Inicializa o formulário de nova conexão.
        Parâmetros:
            parent: widget pai (opcional).
            on_connect: função callback chamada ao clicar em OK.
            on_favoritar: função callback chamada ao clicar em Favoritar.
            on_close_tab: função callback chamada ao clicar em Fechar Aba.
        Não retorna nada.
        """
        super().__init__(parent)
        self.on_connect = on_connect
        self.on_favoritar = on_favoritar
        self.on_close_tab = on_close_tab
        self.setStyleSheet("background: #ffffff;")
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignCenter)
        main_layout.setContentsMargins(32, 32, 32, 32)
        # Formulário centralizado
        form_widget = QWidget()
        form_layout = QVBoxLayout(form_widget)
        # Título e mensagem dentro do formulário
        title = QLabel("Nova Conexão")
        title.setStyleSheet("background: #d3d3d3; font-weight: bold; font-size: 18px; padding: 8px; border: none;")
        title.setAlignment(Qt.AlignCenter)
        form_layout.addWidget(title)
        msg = QLabel("Esta aba ainda não está conectada a um computador remoto.")
        msg.setAlignment(Qt.AlignCenter)
        msg.setStyleSheet("margin: 18px 0 18px 0; color: #444;")
        form_layout.addWidget(msg)
        # Campos do formulário
        fields_widget = QWidget()
        fields_layout = QFormLayout(fields_widget)
        fields_layout.setLabelAlignment(Qt.AlignRight)
        fields_layout.setFormAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        nome_exibicao = QLineEdit()
        nome_exibicao.setMinimumWidth(515)
        nome_exibicao.setMaximumWidth(515)
        fields_layout.addRow("Nome de Exibição:", nome_exibicao)
        self.host_input = QLineEdit()
        self.host_input.setMinimumWidth(515)
        self.host_input.setMaximumWidth(515)
        fields_layout.addRow("Computador:", self.host_input)
        self.user_input = QLineEdit()
        self.user_input.setMinimumWidth(515)
        self.user_input.setMaximumWidth(515)
        fields_layout.addRow("Usuário:", self.user_input)
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.Password)
        self.pass_input.setMinimumWidth(515)
        self.pass_input.setMaximumWidth(515)
        fields_layout.addRow("Senha:", self.pass_input)
        self.domain_input = QLineEdit()
        self.domain_input.setMinimumWidth(515)
        self.domain_input.setMaximumWidth(515)
        fields_layout.addRow("Domínio:", self.domain_input)
        self.port_input = QLineEdit()
        self.port_input.setText('3389')
        self.port_input.setMinimumWidth(515)
        self.port_input.setMaximumWidth(515)
        fields_layout.addRow("Porta RDP:", self.port_input)
        self.nla_checkbox = QCheckBox("Habilitar Autenticação em Nível de Rede (NLA)")
        self.nla_checkbox.setChecked(True)
        fields_layout.addRow("", self.nla_checkbox)
        form_layout.addWidget(fields_widget)
        # Botões dentro do formulário
        btns_widget = QWidget()
        btns_layout = QHBoxLayout(btns_widget)
        self.fav_btn = QPushButton("Salvar como favorito")
        self.fav_btn.clicked.connect(self._on_fav_clicked)
        btns_layout.addWidget(self.fav_btn)
        btns_layout.addStretch(1)
        self.connect_btn = QPushButton("Conectar")
        self.connect_btn.clicked.connect(self._on_ok_clicked)
        btns_layout.addWidget(self.connect_btn)
        form_layout.addWidget(btns_widget)
        main_layout.addWidget(form_widget, alignment=Qt.AlignCenter)

    def _on_ok_clicked(self):
        """
        Chama o callback de conexão com os dados do formulário.
        Não recebe parâmetros e não retorna nada.
        """
        if self.on_connect:
            self.on_connect(self.get_data())

    def _on_close_tab_clicked(self):
        """
        Chama o callback de fechar aba, se fornecido.
        Não recebe parâmetros e não retorna nada.
        """
        if self.on_close_tab:
            self.on_close_tab()

    def _on_fav_clicked(self):
        """
        Chama o callback de favoritar com os dados do formulário.
        Não recebe parâmetros e não retorna nada.
        """
        if self.on_favoritar:
            self.on_favoritar(self.get_favorite_data())

    def get_favorite_data(self):
        """
        Retorna os dados do favorito.
        Retorna:
            tuple: (name, folder, conn_data)
        """
        name = self.host_input.text().strip() or "Favorito"
        folder = ""
        host, username, password, domain, port, nla = self.get_data()
        return (name, folder, {
            'host': host,
            'username': username,
            'password': password,
            'domain': domain,
            'port': port,
            'nla': nla
        })

    def get_data(self):
        """
        Retorna os dados inseridos pelo usuário.
        Retorna:
            tuple: (host, username, password, domain, port, nla)
        """
        host = self.host_input.text().strip()
        username = self.user_input.text().strip()
        password = self.pass_input.text()
        domain = self.domain_input.text().strip()
        try:
            port = int(self.port_input.text())
        except ValueError:
            port = 3389
        nla = self.nla_checkbox.isChecked()
        return (host, username, password, domain, port, nla)

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
