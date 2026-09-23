<?php

declare(strict_types=1);

namespace QUITest\QUI\OAuth\Unit;

use DOMDocument;
use DOMElement;
use DOMXPath;
use PHPUnit\Framework\TestCase;
use QUI\Utils\XML\Settings;

final class UserSettingsTest extends TestCase
{
    public function testUserTabsUseNativeCategoriesWithoutTemplates(): void
    {
        $Document = new DOMDocument();
        self::assertTrue($Document->load($this->userXml()));
        $Path = new DOMXPath($Document);

        self::assertSame(0.0, $Path->evaluate('count(//window/tab | //template)'));
        self::assertSame(2.0, $Path->evaluate('count(//window/categories/category)'));
        self::assertSame('8', $Path->evaluate('string(//category[@name="APITokens"]/@index)'));
        self::assertSame('9', $Path->evaluate('string(//category[@name="OAuthClients"]/@index)'));
        self::assertSame(
            'user.tab.apiTokens',
            $Path->evaluate('string(//category[@name="APITokens"]/title/locale/@var)')
        );
    }

    public function testCategoriesRenderTheirOwnControlImportContainers(): void
    {
        $Settings = new Settings();
        $Settings->setXMLPath('//user/window');

        foreach (['APITokens' => 'UserTokens', 'OAuthClients' => 'UserClients'] as $category => $control) {
            $html = $Settings->getCategoriesHtml([$this->userXml()], $category);
            $Document = new DOMDocument();
            self::assertTrue($Document->loadHTML('<meta charset="UTF-8">' . $html));
            $Path = new DOMXPath($Document);
            $Inputs = $Path->query('//input[@data-qui]');
            self::assertCount(1, $Inputs);
            $Input = $Inputs->item(0);

            self::assertInstanceOf(DOMElement::class, $Input);
            self::assertSame('hidden', $Input->getAttribute('type'));
            self::assertSame(
                'package/quiqqer/oauth-server/bin/backend/controls/' . $control,
                $Input->getAttribute('data-qui')
            );
            // Each control replaces its settings table on import to preserve the grid layout.
            self::assertSame(1.0, $Path->evaluate('count(ancestor::table)', $Input));
        }
    }

    private function userXml(): string
    {
        return dirname(__DIR__, 2) . '/user.xml';
    }
}
