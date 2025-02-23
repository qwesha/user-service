package ru.petproject.ecommerce.user_service.repository;

import ru.petproject.ecommerce.user_service.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    boolean existsByEmail(String email);
}
