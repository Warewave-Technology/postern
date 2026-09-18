-- When each admin last opened the notifications screen.
--
-- ⚠️ THIS IS NOT A NOTIFICATIONS TABLE, AND THE DIFFERENCE IS THE WHOLE
-- POINT. The list itself is still derived on every call: an item vanishes
-- when the work is done, so nothing here can go stale. A real
-- notifications table would keep a row long after the work was finished,
-- until somebody marked it read — and a list that rots is a list nobody
-- reads.
--
-- What is stored is one timestamp per person: everything that started
-- waiting after it is new to them. That is all the badge needs.
--
-- ⚠️ PER PERSON, NOT GLOBAL. One admin opening the screen must not clear
-- the badge for their colleague, who has not seen any of it.
CREATE TABLE notification_reads (
    username TEXT   PRIMARY KEY REFERENCES users (username) ON DELETE CASCADE,
    read_at  BIGINT NOT NULL
);
