CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE tokens (
    id INT PRIMARY KEY,
    user_id INT,
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE FUNCTION generate_token(user_id INT) RETURNS VARCHAR(255) AS $$
DECLARE
    token VARCHAR(255);
BEGIN
    token := md5(random()::text || user_id::text);
    INSERT INTO tokens (user_id, token, expires_at) VALUES (user_id, token, NOW() + INTERVAL '1 hour');
    RETURN token;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION validate_token(token VARCHAR(255)) RETURNS BOOLEAN AS $$
DECLARE
    user_id INT;
BEGIN
    SELECT t.user_id INTO user_id FROM tokens t WHERE t.token = $1 AND t.expires_at > NOW();
    RETURN user_id IS NOT NULL;
END;
$$ LANGUAGE plpgsql;

CREATE PROCEDURE authenticate_user(username VARCHAR(255), password VARCHAR(255))
LANGUAGE plpgsql
AS $$
DECLARE
    user_id INT;
    token VARCHAR(255);
BEGIN
    SELECT u.id INTO user_id FROM users u WHERE u.username = $1 AND u.password = $2;
    IF user_id IS NOT NULL THEN
        token := generate_token(user_id);
        RAISE NOTICE 'Authenticated user %, token: %', $1, token;
    ELSE
        RAISE EXCEPTION 'Invalid username or password';
    END IF;
END;
$$;

INSERT INTO users (id, username, password) VALUES (1, 'admin', 'password123');

CALL authenticate_user('admin', 'password123');

SELECT * FROM tokens;

SELECT validate_token('token_value');