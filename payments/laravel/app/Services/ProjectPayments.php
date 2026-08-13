<?php

namespace App\Services;

use PDO;
use RuntimeException;

final class ProjectPayments
{
    public const CATALOG = [
        'monthly' => ['productKey'=>'pro','currency'=>'USD','unitAmount'=>1500,'type'=>'recurring','interval'=>'month'],
        'lifetime' => ['productKey'=>'pro','currency'=>'USD','unitAmount'=>9900,'type'=>'one_time','interval'=>null],
    ];

    private PDO $database;

    public function __construct(
        private readonly string $secret,
        private readonly string $environmentId,
        string $databasePath,
    ) {
        if (strlen($secret) < 32) throw new RuntimeException('Webhook secret must contain at least 32 bytes.');
        $directory = dirname($databasePath);
        if (!is_dir($directory)) mkdir($directory, 0770, true);
        $this->database = new PDO('sqlite:'.$databasePath, options: [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $this->database->exec('CREATE TABLE IF NOT EXISTS customer_subjects(customer_id TEXT PRIMARY KEY, subject TEXT NOT NULL UNIQUE); CREATE TABLE IF NOT EXISTS webhook_inbox(event_id TEXT PRIMARY KEY, body_digest TEXT NOT NULL); CREATE TABLE IF NOT EXISTS entitlements(subject TEXT NOT NULL, entitlement TEXT NOT NULL, quantity INTEGER NOT NULL, PRIMARY KEY(subject, entitlement));');
    }

    public function checkout(string $subject, array $input): array
    {
        if (array_keys($input) !== ['priceKey'] || !isset(self::CATALOG[$input['priceKey']])) throw new RuntimeException('Use one trusted catalog priceKey.');
        $customer = self::customerId($subject);
        $statement = $this->database->prepare('INSERT OR REPLACE INTO customer_subjects(customer_id, subject) VALUES (?, ?)');
        $statement->execute([$customer, $subject]);
        return ['url'=>sprintf('https://simulator.invalid/checkout/%s/%s/%s', rawurlencode($this->environmentId), rawurlencode($customer), rawurlencode($input['priceKey']))];
    }

    public function portal(string $subject): array
    {
        $customer = self::customerId($subject);
        $statement = $this->database->prepare('INSERT OR REPLACE INTO customer_subjects(customer_id, subject) VALUES (?, ?)');
        $statement->execute([$customer, $subject]);
        return ['url'=>sprintf('https://simulator.invalid/portal/%s/%s', rawurlencode($this->environmentId), rawurlencode($customer))];
    }

    public function acceptWebhook(string $rawBody, string $signature, ?int $now = null): bool
    {
        if (strlen($rawBody) > 131072) throw new RuntimeException('Webhook exceeds the size limit.');
        $parts = [];
        foreach (explode(';', $signature) as $part) { if (str_contains($part, '=')) { [$key,$value] = explode('=', $part, 2); $parts[$key]=$value; } }
        $timestamp = filter_var($parts['ts'] ?? null, FILTER_VALIDATE_INT);
        if ($timestamp === false || abs(($now ?? time()) - $timestamp) > 300) throw new RuntimeException('Invalid webhook signature.');
        $expected = hash_hmac('sha256', $timestamp.':'.$rawBody, $this->secret);
        if (!hash_equals($expected, $parts['h1'] ?? '')) throw new RuntimeException('Invalid webhook signature.');
        $event = json_decode($rawBody, true, flags: JSON_THROW_ON_ERROR);
        if (($event['data']['custom_data']['vibenest_environment_id'] ?? null) !== $this->environmentId) throw new RuntimeException('Webhook environment mismatch.');
        $this->validateEvent($event);
        $this->database->beginTransaction();
        try {
            $insert = $this->database->prepare('INSERT INTO webhook_inbox(event_id, body_digest) VALUES (?, ?)');
            $insert->execute([$event['event_id'], hash('sha256', $rawBody)]);
        } catch (\PDOException $error) {
            $this->database->rollBack();
            if ($error->getCode() === '23000') return false;
            throw $error;
        }
        if (($event['event_type'] ?? null) === 'transaction.completed') {
            $lookup = $this->database->prepare('SELECT subject FROM customer_subjects WHERE customer_id = ?');
            $lookup->execute([$event['data']['customer_id'] ?? null]);
            if ($subject = $lookup->fetchColumn()) {
                $grant = $this->database->prepare("INSERT INTO entitlements(subject, entitlement, quantity) VALUES (?, 'premium-access', 1) ON CONFLICT(subject, entitlement) DO UPDATE SET quantity=excluded.quantity");
                $grant->execute([$subject]);
            }
        }
        $this->database->commit();
        return true;
    }

    public function entitlementQuantity(string $subject): int
    {
        $query = $this->database->prepare("SELECT quantity FROM entitlements WHERE subject=? AND entitlement='premium-access'");
        $query->execute([$subject]);
        return (int) ($query->fetchColumn() ?: 0);
    }

    public static function customerId(string $subject): string { return 'sim_customer_'.substr(hash('sha256', $subject), 0, 24); }

    private function validateEvent(array $event): void
    {
        if (($event['event_type'] ?? null) !== 'transaction.completed') return;
        $data=$event['data'] ?? []; $items=$data['items'] ?? null;
        if (($data['status'] ?? null) !== 'completed' || !is_array($items) || count($items) !== 1) throw new RuntimeException('Invalid completed transaction.');
        $item=$items[0]; $price=self::CATALOG[$item['price_id'] ?? ''] ?? null; $totals=$data['details']['totals'] ?? [];
        if ($price===null || ($item['product_id'] ?? null)!==$price['productKey'] || ($item['quantity'] ?? null)!==1 || ($totals['total'] ?? null)!==(string)$price['unitAmount'] || ($totals['currency_code'] ?? null)!==$price['currency']) throw new RuntimeException('Transaction does not match the trusted catalog.');
    }
}
