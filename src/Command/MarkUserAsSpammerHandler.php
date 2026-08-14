<?php

namespace ArchLinux\AntiSpam\Command;

use Carbon\Carbon;
use Flarum\Discussion\Discussion;
use Flarum\Discussion\Command\EditDiscussion;
use Flarum\Post\Command\EditPost;
use Flarum\Post\Post;
use Flarum\User\Command\EditUser;
use Illuminate\Contracts\Bus\Dispatcher;

class MarkUserAsSpammerHandler
{
    private const SUSPENSION_YEARS = 20;

    public function __construct(private Dispatcher $bus)
    {
    }

    public function handle(MarkUserAsSpammer $command): void
    {
        $user = $command->user;
        $actor = $command->actor;

        $user->discussions()->whereNull('hidden_at')->eachById(function (Discussion $discussion) use ($actor) {
            $this->bus->dispatch(new EditDiscussion($discussion->id, $actor, [
                'attributes' => ['isHidden' => true],
            ]));
        });

        $user->posts()->whereNull('hidden_at')->eachById(function (Post $post) use ($actor) {
            $this->bus->dispatch(new EditPost($post->id, $actor, [
                'attributes' => ['isHidden' => true],
            ]));
        });

        $until = Carbon::now()->addYears(self::SUSPENSION_YEARS);

        /** @phpstan-ignore-next-line */
        if ($user->suspended_until === null || $user->suspended_until->lessThan($until)) {
            $this->bus->dispatch(new EditUser($user->id, $actor, [
                'attributes' => ['suspendedUntil' => $until->toIso8601String()],
            ]));
        }
    }
}
