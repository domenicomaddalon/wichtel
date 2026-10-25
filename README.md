# Wichtel-App 1.0

Statische WebApp mit Supabase-Authentifizierung und geheimer serverseitiger Auslosung.

## Einrichtung
1. Supabase-Projekt erstellen.
2. Inhalt von `supabase.sql` im Supabase SQL Editor ausführen.
3. Unter Authentication > Users ein Admin-Konto mit E-Mail und Passwort anlegen. Öffentliche Registrierungen deaktivieren.
4. In GitHub Pages `main` und `/(root)` auswählen (Hinweis: Bei privaten Repositories kann GitHub Pages einen entsprechenden Tarif voraussetzen).
5. WebApp öffnen und Supabase Project URL sowie **publishable/anon** Key eingeben. Niemals den service_role Key verwenden.
6. Als Admin anmelden, Wichtelrunde anlegen, Teilnehmer erfassen, Ausschlüsse definieren und auslosen.
7. Öffentliche HTTPS-URL der App speichern. Für jeden Teilnehmer über „E-Mail öffnen“ die persönliche Einladung im eigenen E-Mail-Programm absenden.

## Sicherheit
- Zuordnungen werden nicht im Admin-Dashboard angezeigt; die Auslosung erfolgt serverseitig.
- Wer Zugriff auf die Versandlinks hat, kann die Lose dennoch öffnen. Daher ist vollständige Geheimhaltung gegenüber dem Admin bei manuellem Versand **nicht** garantiert.
- Datenbankadministratoren können auf Datenbankinhalte zugreifen.
- Das Öffnen des E-Mail-Programms ist keine Versandbestätigung.
- Die App ist vor produktivem Einsatz zu testen.
