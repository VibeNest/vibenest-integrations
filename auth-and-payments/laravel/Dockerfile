FROM composer:2 AS vendor
WORKDIR /repo
COPY . .
WORKDIR /repo/auth-and-payments/laravel
RUN composer install --no-dev --classmap-authoritative --no-interaction
FROM php:8.4-cli
RUN docker-php-ext-install pdo_sqlite
WORKDIR /repo
COPY --from=vendor /repo /repo
WORKDIR /repo/auth-and-payments/laravel
CMD ["php","artisan","serve","--host=0.0.0.0","--port=8080"]
