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
nützlich, wenn temporär (z.B. zu Testzwecken) die OAuth-Authentifizierung für die REST API deaktiviert werden soll.
* **Token Lebenszeit** - Gibt in Sekunden an, wie lange ein OAuth-Token gültig bleibt. Ein OAuth-Token erlaubt dem
Besitzer spezifische REST API Anfragen im festgelegten Zeitraum.

### OAuth-Client erstellen / bearbeiten
QUIQQER OAuth-Clients werden über Benutzer konfiguriert. Dies erleichtert Administratoren die Zuweisung von bestimmten
Clients zu Personen.

**WICHTIG:** Aktuell ist für eine OAuth-Authentifizierung eine benutzerspezifische Authentifizierung **nicht** relevant.
Das heißt derjenige, welcher die REST API benutzen will, muss sich lediglich mit der entsprechenden Kombination
aus **Client-ID** und **Client-Secret** authentifizieren. Ein QUIQQER-Benutzername oder -Passwort sind dafür nicht erforderlich.
Dies kann sich in Zukunft ändern, wenn weitere OAuth-Authentifizierungsmethoden unterstützt werden.

Erstellung eines neuen OAuth-Clients:
1. Benutzerverwaltung öffnen (`Verwaltung -> Benutzerverwaltung -> Benutzer`).
2. Ein Benutzer-Panel öffnen.
3. Reiter `OAuth-Clients`
4. In der Übersichtstabelle auf `Client hinzufügen` klicken.

Einzelheiten zur Konfiguration:
* **Titel** - Eine interne Beschreibung des Clients, zur einfacheren Identifizierung / Zuweisung (nur für Administratoren sichtbar)
* **Zugriffs-Einstellungen** - s. [Zugriffseinstellungen](#Zugriffs-Einstellungen)

Nach der Erstellung wird der Client in der Übersichtsliste angezeigt. Er ist jetzt aktiv und kann verwendet werden (im Rahmen
der Zugriffsbeschränkungen). 

#### Detail-Ansicht

In der **Detail-Ansicht** können die **Client-ID** und das **Client-Secret** eingesehen werden. Hierzu genügt ein Doppelklick
auf einen Tabelleneintrag oder die Markierung einer Tabellenzeile und ein Klick auf **"Client editieren"**.

In der Detail-Ansicht können ebenfalls die [Zugriffseinstellungen](#Zugriffs-Einstellungen) angepasst werden.

#### Zugriffs-Einstellungen
Die Zugriffs-Einstellungen regeln, welche REST API Endpunkte für den jeweiligen Client verfügbar sind und wie sie zeitlich
und/oder bzgl. der Anzahl der Aufrufe begrenzt sind. Die Konfiguration ist wie folgt aufgebaut:

* **Scope (Einstigspunkt)** - Beschreibt den konkreten REST API Einstiegspunkt, der per HTTP(S)-Request angefragt wird und
über den Ressourcen verwaltet werden. Hier sind **alle** Einstiegspunkte von allen REST API-Providern gelistet, die im
aktuellen QUIQQER-System registriert sind.
  * **Hinweis:** Die speziellen `/oauth/*`-Einstiegspunkte sind hier nicht gelistet, da sie besonderen Regelungen unterworfen
  sind, die für die interne Funktionsweise des QUIQQER OAuth Servers verwendet werden.
* **Aktiv-Status** - Sagt aus, ob ein Einstiegspunkt grundsätzlich verfügbar ist. Ein nicht verfügbarer Einstiegspunkt
erzeugt einen `404`-Statuscode, wenn er angefragt wird. **Standardmäßig** ist jeder Einstiegspunkt **deaktiviert** und muss manuell
aktiviert werden.
* **Aufrufe** - An dieser Stelle können die Beschränkungen für Einstiegspunkte konfiguriert werden:
  * **Unbegrenzt** - Ist diese Option aktiviert, existieren keine Aufruf-Beschränkungen für den Einstiegspunkt. Ist sie deaktiviert,
  sind folgende Optionen verfügbar:
  * **Max. Anzahl Aufrufe** - Sagt aus, wieviele Anfragen maximal im gewählten Intervall durchgeführt werden dürfen
  * **Intervall** - Gibt den zeitlichen Intervall an, auf den sich die "Max. Anzahl Aufrufe" bezieht. **"Insgesamt"** bedeutet,
  dass die Anzahl aufrufe unabhängig eines Zeitraum durchgeführt werden darf. 
  
Im **Detail-Fenster** eines OAuth-Clients können an dieser Stelle auch die durchgeführten Abfragen eingesehen werden. Die
Abfrage-Übersicht erscheint, sobald der entsprechende Einstiegspunkt das erste Mal verwendet wird.

Mit der Funktion **"Abfragen zurücksetzen"** können die Abfragen für den eingestellten Intervall auf 0 zurückgesetzt werden.