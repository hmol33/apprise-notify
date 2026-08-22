"""
Apprise plugin for pwnagotchi.

Sends notifications (email, Telegram, Discord, whatever Apprise supports)
on events such as captured handshakes or peer detection.

Configuration goes in /etc/pwnagotchi/config.d/ (or config.toml):

    [main.plugins.apprisenotify]
    enabled = true
    config_path = "/home/pi/.config/apprise.yml"
    urls = ["mailto://user:pass@example.com"]   # optional extra urls
    notify_on_handshake = true
    notify_on_peer = false
"""
import logging
import os

import apprise
import pwnagotchi.plugins as plugins


class Apprise(plugins.Plugin):
    __author__ = 'bauke.molenaar@gmail.com'
    __version__ = '1.1.0'
    __license__ = 'GPL3'
    __description__ = 'An Apprise plugin for pwnagotchi: notifications via email/Telegram/Discord/etc.'
    __name__ = 'Apprise'
    __help__ = """
Configure notification targets either in an apprise YAML config file or as
urls in the pwnagotchi plugin config. Events to notify on are configurable.
"""

    def __init__(self):
        logging.debug("Apprise plugin created")
        self.apobj = None
        self._last_peer = set()

    def _setup(self):
        """Build the Apprise object once, from plugin options."""
        if self.apobj is not None:
            return True
        opts = self.options or {}
        apobj = apprise.Apprise()

        config_path = opts.get('config_path', '/home/pi/.config/apprise.yml')
        if os.path.exists(config_path):
            config = apprise.AppriseConfig()
            config.add(config_path)
            apobj.add(config)

        urls = opts.get('urls', [])
        if isinstance(urls, str):
            urls = [u.strip() for u in urls.split(',') if u.strip()]
        for url in urls:
            apobj.add(url)

        if not apobj.servers():
            logging.warning("apprise-notify: no notification targets configured")
            return False
        self.apobj = apobj
        return True

    def _notify(self, title, body):
        if not self._setup():
            return
        try:
            result = self.apobj.notify(title=title, body=body)
            if result is False:
                logging.warning("apprise-notify: one or more notifications failed")
        except Exception as e:
            logging.error("apprise-notify: %s", e)

    # called when the plugin is loaded
    def on_loaded(self):
        logging.debug("Apprise plugin loaded")
        # validate early so misconfiguration shows up in the log right away
        self._setup()

    # called when a new handshake is captured
    def on_handshake(self, agent, filename, access_point, client_station):
        opts = self.options or {}
        if not opts.get('notify_on_handshake', True):
            return
        ap_name = access_point.get('hostname', access_point) if isinstance(access_point, dict) else access_point
        self._notify(
            title='Handshake captured',
            body=f'New handshake for {ap_name} saved to {filename}',
        )

    # called when a new peer is detected
    def on_peer_detected(self, agent, peer):
        opts = self.options or {}
        if not opts.get('notify_on_peer', False):
            return
        identity = peer.get('identity', peer) if isinstance(peer, dict) else peer
        if identity in self._last_peer:
            return
        self._last_peer.add(identity)
        self._notify(title='Peer detected', body=f'New peer: {identity}')

    # called when a known peer is lost
    def on_peer_lost(self, agent, peer):
        identity = peer.get('identity', peer) if isinstance(peer, dict) else peer
        self._last_peer.discard(identity)

    # called when http://<host>:<port>/plugins/<plugin>/ is called
    def on_webhook(self, path, request):
        logging.debug("Apprise Webhook clicked!")
        return "ok"

    def on_unload(self, ui):
        logging.debug("Apprise plugin unloaded")

    def on_internet_available(self, agent):
        pass

    def on_ui_setup(self, ui):
        pass

    def on_ui_update(self, ui):
        pass

    def on_display_setup(self, display):
        pass
