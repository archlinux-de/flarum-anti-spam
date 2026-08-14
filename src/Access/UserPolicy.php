<?php

namespace ArchLinux\AntiSpam\Access;

use Flarum\User\Access\AbstractPolicy;
use Flarum\User\User;

class UserPolicy extends AbstractPolicy
{
    public function spamblock(User $actor, User $user): ?bool
    {
        if ($actor->id === $user->id || $user->can('user.spamblock')) {
            return false;
        }

        return null;
    }
}
