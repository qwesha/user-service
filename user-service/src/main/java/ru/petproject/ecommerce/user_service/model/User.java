package ru.petproject.ecommerce.user_service.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    private String email;
    private String password;
    private String name;
    private String role; // Роли: USER, ADMIN
    private LocalDateTime createdAt;
}