-- Record each enrolled agent's operating system so the dashboard can show an
-- OS-specific status icon (Linux penguin / Windows four-pane logo) in place of a
-- plain status dot. Reported by the agent on the WebSocket `Hello` frame
-- (`std::env::consts::OS`). NULL for agents enrolled before OS reporting existed,
-- until they next reconnect with a build that reports it.
ALTER TABLE agents ADD COLUMN os text;
