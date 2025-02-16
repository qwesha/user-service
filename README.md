# 🛒 E-Commerce Platform (Пет-проект)

### 📌 Описание

Микросервисная платформа для интернет-магазина с корзиной, заказами и оплатой.

## ⚙️ Технологии:

- **Backend:** Java 21, Spring Boot 3.3.2
- **База данных:** PostgreSQL, Redis
- **Сообщения:** RabbitMQ, Kafka
- **Поиск:** Elasticsearch
- **Платежи:** Stripe API
- **Контейнеризация:** Docker

## 🛠️ Структура микросервисов:

| Микросервис         | Описание                          | Технологии                        |
|---------------------|-----------------------------------|-----------------------------------|
| **User Service**    | Регистрация, авторизация, профили | Spring Boot, JWT, PostgreSQL      |
| **Product Service** | Управление товарами               | Spring Boot, ElasticSearch        |
| **Order Service**   | Корзина, заказы                   | Spring Boot, PostgreSQL           |
| **Payment Service** | Оплата                            | Spring Boot, Stripe API, RabbitMQ |
| **Review Service**  | Отзывы, рекомендации              | Spring Boot, Kafka, Redis         |
---