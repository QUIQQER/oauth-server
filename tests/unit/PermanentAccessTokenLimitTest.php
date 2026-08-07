<?php

namespace QUITest\QUI\OAuth\Unit;

use PHPUnit\Framework\TestCase;
use QUI\Groups\Group;
use QUI\OAuth\Clients\Handler;
use QUI\OAuth\Permission;
use QUI\Users\User;

final class PermanentAccessTokenLimitTest extends TestCase
{
    public function testUnlimitedValueOverridesEveryFiniteLimit(): void
    {
        $permission = Permission::MAX_NUMBER_OF_PERMANENT_ACCESS_TOKENS->value;
        $Groups = [];

        foreach ([0, 1, 100] as $finiteLimit) {
            $Group = $this->createMock(Group::class);
            $Group->expects(self::once())
                ->method('hasPermission')
                ->with($permission)
                ->willReturn($finiteLimit);
            $Groups[] = $Group;
        }

        $User = $this->createMock(User::class);
        $User->expects(self::once())
            ->method('getGroups')
            ->willReturn($Groups);
        $User->expects(self::once())
            ->method('hasPermission')
            ->with($permission)
            ->willReturn('-1');
        $User->expects(self::never())
            ->method('getPermission');

        self::assertNull(Handler::getMaxNumberOfPermanentAccessTokens($User));
    }
}
