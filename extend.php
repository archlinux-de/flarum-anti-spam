<?php

namespace ArchLinux\AntiSpam;

use ArchLinux\AntiSpam\Console\CheckAgainstStopForumSpamBlockLists;
use ArchLinux\AntiSpam\Console\DownloadStopForumSpamBlockLists;
use ArchLinux\AntiSpam\Access\UserPolicy;
use ArchLinux\AntiSpam\Api\AddUserPermissions;
use ArchLinux\AntiSpam\Api\Controllers\MarkUserAsSpammerController;
use ArchLinux\AntiSpam\Validator\RegistrationHandler;
use Flarum\Api\Serializer\UserSerializer;
use Flarum\Extend;
use Flarum\User\Event\Saving;
use Illuminate\Console\Scheduling\Event;
use Flarum\User\User;

return [
    (new Extend\Frontend('forum'))
        ->js(__DIR__ . '/js/dist/forum.js'),
    (new Extend\Frontend('admin'))
        ->js(__DIR__ . '/js/dist/admin.js'),
    new Extend\Locales(__DIR__ . '/locale'),
    (new Extend\Routes('api'))
        ->post('/users/{id}/spamblock', 'archlinux-de-anti-spam.spamblock', MarkUserAsSpammerController::class),
    (new Extend\ApiSerializer(UserSerializer::class))
        ->attributes(AddUserPermissions::class),
    (new Extend\Policy())
        ->modelPolicy(User::class, UserPolicy::class),
    (new Extend\Event())->listen(Saving::class, RegistrationHandler::class),
    (new Extend\Console())
        ->command(DownloadStopForumSpamBlockLists::class)
        ->schedule(DownloadStopForumSpamBlockLists::class, function (Event $event) {
            $event->withoutOverlapping();
            $event->dailyAt(sprintf('%02d:%02d', rand(0, 5), rand(0, 59)));
        })
        ->command(CheckAgainstStopForumSpamBlockLists::class),
];
