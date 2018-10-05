QUIQQER OAuth Server - Dokumentation (Administration)
===
Dieses Dokument beschreibt, wie man mit dem `quiqqer/oauth-server`-Paket OAuth Clients erstellt und konfiguriert. Ferner
werden an relevanten Stellen die technischen Hintergründe erläutert.

Grundsätzlich ist das `quiqqer/oauth-server`-Paket dazu gedacht, die Endpunkte aller REST API Provider, die ein bzw. mehrere
QUIQQER-Module im System registrieren (via `package.xml`) mittels einer OAuth2-Authentifizierung abzusichern und einem
speziellen Middleware-Controller, welcher sich vor jeder REST API-Anfrage einklinkt, zu limitieren.

Jeder REST API Endpunkt, den ein QUIQQER-Modul registriert, wird vom OAuth-Server als OAuth-`scope` interpretiert.

**HINWEIS:** Dieses Modul bietet z.Z. **noch nicht** die Möglichkeit, fremden Services Daten über QUIQQER-Benutzer bzw. -Ressourcen
über eine OAuth-Authentifizierung (via `Auhtorization Code`/`Implicit`) zur Verfügung zu stellen.

### Grundkonfiguration
Im QUIQQER-Backend kann über `Einstellungen -> OAuth` die Konfiguration aufgerufen werden.

* **OAuth2 Status** - Diese Option schaltet die Funktionalität dieses Moduls grundsätzlich an bzw. aus. Dies ist z.B. dann
nützlich, wenn temporär (z.B. zu Testzwecken)