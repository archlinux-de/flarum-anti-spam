<?php

namespace ArchLinux\AntiSpam\Command;

use Flarum\User\User;

class MarkUserAsSpammer
{
    public function __construct(
        public User $user,
        public User $actor
    ) {
    }
}
