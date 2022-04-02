CREATE TABLE users (id SERIAL PRIMARY KEY, username TEXT, password TEXT, admin BOOLEAN);
CREATE TABLE notes (id SERIAL PRIMARY KEY, content TEXT, removed BOOLEAN, user_id REFERENCES users);