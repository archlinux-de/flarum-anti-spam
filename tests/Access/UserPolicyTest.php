<?php

namespace ArchLinux\AntiSpam\Test\Access;

use ArchLinux\AntiSpam\Access\UserPolicy;
use Flarum\User\User;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class UserPolicyTest extends TestCase
{
    private function createUser(int $id): User&MockObject
    {
        $user = $this->createMock(User::class);
        $user->method('__get')->willReturnCallback(fn (string $key) => $key === 'id' ? $id : null);

        return $user;
    }

    public function testDeniesMarkingYourselfAsASpammer(): void
    {
        $actor = $this->createUser(1);

        $policy = new UserPolicy();

        $this->assertFalse($policy->spamblock($actor, $actor));
    }

    public function testDeniesMarkingAnotherModeratorAsASpammer(): void
    {
        $actor = $this->createUser(1);
        $target = $this->createUser(2);
        $target->expects($this->once())->method('can')->with('user.spamblock')->willReturn(true);

        $policy = new UserPolicy();

        $this->assertFalse($policy->spamblock($actor, $target));
    }

    public function testDefersPermissionCheckForRegularUsers(): void
    {
        $actor = $this->createUser(1);
        $target = $this->createUser(2);
        $target->expects($this->once())->method('can')->with('user.spamblock')->willReturn(false);

        $policy = new UserPolicy();

        $this->assertNull($policy->spamblock($actor, $target));
    }
}
