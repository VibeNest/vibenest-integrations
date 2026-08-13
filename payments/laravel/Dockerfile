FROM composer:2 AS vendor
WORKDIR /app
COPY composer.json composer.lock ./
RUN composer install --no-dev --classmap-authoritative --no-interaction
FROM php:8.4-cli
RUN docker-php-ext-install pdo_sqlite
WORKDIR /app
COPY --from=vendor /app/vendor ./vendor
COPY . .
CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=8080"]
