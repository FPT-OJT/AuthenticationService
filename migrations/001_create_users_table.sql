-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_name VARCHAR(255) UNIQUE,
    google_id VARCHAR(255) UNIQUE,
    email VARCHAR(255) UNIQUE,
    password VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'CUSTOMER',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

-- Create index for user queries
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_user_name ON users(user_name);
CREATE INDEX idx_users_google_id ON users(google_id);

INSERT INTO users (id, user_name, google_id, email, password, created_at, updated_at, deleted_at) VALUES
('e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8a9b', 'john_smith', NULL, 'john.smith@gmail.com', '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2024-11-20 14:30:00', '2025-01-20 16:45:00', NULL),
('f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f8a9b0c', 'sarah_johnson', NULL, 'sarah.johnson@outlook.com', '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2024-12-01 09:00:00', '2025-01-21 10:30:00', NULL),
('a7b8c9d0-e1f2-4a3b-4c5d-6e7f8a9b0c1d', 'michael_brown', NULL, 'michael.brown@yahoo.com', '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2024-12-05 13:15:00', '2025-01-22 08:20:00', NULL),
('b8c9d0e1-f2a3-4b4c-5d6e-7f8a9b0c1d2e', 'emily_davis', NULL, 'emily.davis@gmail.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2024-12-10 16:45:00', '2025-01-23 14:00:00', NULL),
('c9d0e1f2-a3b4-4c5d-6e7f-8a9b0c1d2e3f', 'david_wilson', NULL, 'david.wilson@gmail.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2024-12-15 11:00:00', '2025-01-24 09:30:00', NULL),
('d0e1f2a3-b4c5-4d6e-7f8a-9b0c1d2e3f4a', 'jessica_moore', NULL, 'jessica.moore@outlook.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2024-12-18 08:30:00', '2025-01-25 11:15:00', NULL),
('e1f2a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b', 'james_taylor', NULL, 'james.taylor@gmail.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2024-12-20 15:20:00', '2025-01-26 13:40:00', NULL),
('f2a3b4c5-d6e7-4f8a-9b0c-1d2e3f4a5b6c', 'ashley_anderson', NULL, 'ashley.anderson@yahoo.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2024-12-22 10:10:00', '2025-01-27 15:25:00', NULL),
('a3b4c5d6-e7f8-4a9b-0c1d-2e3f4a5b6c7d', 'robert_thomas', NULL, 'robert.thomas@gmail.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2025-01-02 12:00:00', '2025-01-27 10:00:00', NULL),
('b4c5d6e7-f8a9-4b0c-1d2e-3f4a5b6c7d8e', 'amanda_jackson', NULL, 'amanda.jackson@outlook.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2025-01-05 14:35:00', '2025-01-27 16:50:00', NULL),
('c5d6e7f8-a9b0-4c1d-2e3f-4a5b6c7d8e9f', 'christopher_white', NULL, 'christopher.white@gmail.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2025-01-08 09:45:00', '2025-01-28 08:10:00', NULL),
('d6e7f8a9-b0c1-4d2e-3f4a-5b6c7d8e9f0a', 'melissa_harris', NULL, 'melissa.harris@yahoo.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2025-01-10 11:30:00', '2025-01-28 09:20:00', NULL),
('e7f8a9b0-c1d2-4e3f-4a5b-6c7d8e9f0a1b', 'daniel_martin', NULL, 'daniel.martin@gmail.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2025-01-12 13:15:00', '2025-01-28 11:35:00', NULL),
('f8a9b0c1-d2e3-4f4a-5b6c-7d8e9f0a1b2c', 'jennifer_garcia', NULL, 'jennifer.garcia@outlook.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2025-01-14 15:50:00', '2025-01-28 12:45:00', NULL),
('a9b0c1d2-e3f4-4a5b-6c7d-8e9f0a1b2c3d', 'matthew_martinez', NULL, 'matthew.martinez@gmail.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2025-01-16 08:20:00', '2025-01-28 14:00:00', NULL),
('b0c1d2e3-f4a5-4b6c-7d8e-9f0a1b2c3d4e', 'stephanie_robinson', NULL, 'stephanie.robinson@yahoo.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2025-01-18 10:40:00', '2025-01-28 15:30:00', NULL),
('c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f', 'anthony_clark', NULL, 'anthony.clark@gmail.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2025-01-20 09:15:00', '2025-01-28 16:20:00', NULL),
('d2e3f4a5-b6c7-4d8e-9f0a-1b2c3d4e5f6a', 'nicole_rodriguez', NULL, 'nicole.rodriguez@outlook.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2025-01-22 11:30:00', '2025-01-28 17:10:00', NULL),
('e3f4a5b6-c7d8-4e9f-0a1b-2c3d4e5f6a7b', 'william_lewis', NULL, 'william.lewis@gmail.com',  '$2a$10$GiGMU5Dhf47Ln6LUVQ9Wv.6pVumI3BqigTVCOZ502vpxdcJBAC8eS',  '2025-01-24 14:45:00', '2025-01-28 18:00:00', NULL);

-- +goose Down
-- SQL in section 'Down' is executed when this migration is rolled back

DROP TABLE IF EXISTS users;