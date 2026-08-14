<?php

namespace ArchLinux\AntiSpam\Api\Controllers;

use ArchLinux\AntiSpam\Command\MarkUserAsSpammer;
use Flarum\Http\RequestUtil;
use Flarum\User\User;
use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Support\Arr;
use Laminas\Diactoros\Response\EmptyResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class MarkUserAsSpammerController implements RequestHandlerInterface
{
    public function __construct(private Dispatcher $bus)
    {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $actor = RequestUtil::getActor($request);
        /** @var User $user */
        $user = User::query()->findOrFail(Arr::get($request->getQueryParams(), 'id'));

        $actor->assertCan('spamblock', $user);

        $this->bus->dispatch(new MarkUserAsSpammer($user, $actor));

        return new EmptyResponse();
    }
}
