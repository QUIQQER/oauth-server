<?php

namespace QUI\OAuth\Consent;

final class Presentation
{
    private const MAX_SECTIONS = 20;
    private const MAX_ITEMS_PER_SECTION = 500;

    /**
     * @var list<array{
     *     title: string,
     *     items: list<array{name: string, type: string}>
     * }>
     */
    private array $sections = [];

    public function __construct(
        private string $title,
        private string $description
    ) {
        $this->title = self::normalizeText($title, 'title', 250);
        $this->description = self::normalizeText(
            $description,
            'description',
            2000
        );
    }

    public function getTitle(): string
    {
        return $this->title;
    }

    public function setTitle(string $title): self
    {
        $this->title = self::normalizeText($title, 'title', 250);

        return $this;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function setDescription(string $description): self
    {
        $this->description = self::normalizeText(
            $description,
            'description',
            2000
        );

        return $this;
    }

    public function clearSections(): self
    {
        $this->sections = [];

        return $this;
    }

    /**
     * @param list<string|array{name: string, type?: string}> $items
     */
    public function addSection(string $title, array $items): self
    {
        if (count($this->sections) >= self::MAX_SECTIONS) {
            throw new \OverflowException(
                'An OAuth consent presentation may contain at most '
                . self::MAX_SECTIONS
                . ' sections.'
            );
        }

        if (count($items) > self::MAX_ITEMS_PER_SECTION) {
            throw new \OverflowException(
                'An OAuth consent section may contain at most '
                . self::MAX_ITEMS_PER_SECTION
                . ' items.'
            );
        }

        $normalizedItems = [];
        $seen = [];

        foreach ($items as $item) {
            if (is_string($item)) {
                $name = $item;
                $type = '';
            } else {
                $name = $item['name'] ?? '';
                $type = $item['type'] ?? '';
            }

            $name = self::normalizeText($name, 'item name', 500);
            $type = trim($type);

            if ($type !== '') {
                $type = self::normalizeText($type, 'item type', 100);
            }

            $key = $type . "\0" . $name;

            if (isset($seen[$key])) {
                continue;
            }

            $seen[$key] = true;
            $normalizedItems[] = [
                'name' => $name,
                'type' => $type
            ];
        }

        if ($normalizedItems === []) {
            return $this;
        }

        $this->sections[] = [
            'title' => self::normalizeText(
                $title,
                'section title',
                250
            ),
            'items' => $normalizedItems
        ];

        return $this;
    }

    /**
     * @return list<array{
     *     title: string,
     *     items: list<array{name: string, type: string}>
     * }>
     */
    public function getSections(): array
    {
        return $this->sections;
    }

    private static function normalizeText(
        string $value,
        string $field,
        int $maxLength
    ): string {
        $value = trim($value);

        if ($value === '') {
            throw new \InvalidArgumentException(
                'OAuth consent ' . $field . ' must not be empty.'
            );
        }

        if (mb_strlen($value) > $maxLength) {
            throw new \InvalidArgumentException(
                'OAuth consent ' . $field . ' is too long.'
            );
        }

        if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', $value) === 1) {
            throw new \InvalidArgumentException(
                'OAuth consent ' . $field . ' contains control characters.'
            );
        }

        return $value;
    }
}
