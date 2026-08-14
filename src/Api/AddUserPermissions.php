<?php

namespace ArchLinux\AntiSpam\Api;

use Flarum\Api\Serializer\UserSerializer;
use Flarum\User\User;

class AddUserPermissions
{
    /**
     * @param array<string, mixed> $attributes
     * @return array<string, mixed>
     */
    public function __invoke(UserSerializer $serializer, User $user, array $attributes): array
    {
        $attributes['canSpamblock'] = $serializer->getActor()->can('spamblock', $user);

        return $attributes;
    }
}
