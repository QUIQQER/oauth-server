<?php

namespace QUITest\QUI\OAuth\Unit;

use PHPUnit\Framework\TestCase;
use QUI\OAuth\Consent\Presentation;

final class ConsentPresentationTest extends TestCase
{
    public function testPresentationNormalizesAndDeduplicatesSections(): void
    {
        $Presentation = new Presentation(' Initial title ', ' Initial description ');
        $Presentation
            ->setTitle('Customized title')
            ->setDescription('Customized description')
            ->addSection('Available functions', [
                'project_information',
                ['type' => 'Tool', 'name' => 'project_update'],
                ['type' => 'Tool', 'name' => 'project_update']
            ])
            ->addSection('Empty section', []);

        self::assertSame('Customized title', $Presentation->getTitle());
        self::assertSame(
            'Customized description',
            $Presentation->getDescription()
        );
        self::assertSame([
            [
                'title' => 'Available functions',
                'items' => [
                    [
                        'name' => 'project_information',
                        'type' => ''
                    ],
                    [
                        'name' => 'project_update',
                        'type' => 'Tool'
                    ]
                ]
            ]
        ], $Presentation->getSections());

        $Presentation->clearSections();
        self::assertSame([], $Presentation->getSections());
    }

    public function testPresentationRejectsInvalidText(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new Presentation('Title', 'Description'))->addSection(
            'Functions',
            [['name' => "in\0valid"]]
        );
    }
}
