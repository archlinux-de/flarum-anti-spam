<?php

namespace ArchLinux\AntiSpam\Tests\Integration;

use Carbon\Carbon;
use Flarum\Testing\integration\TestCase;

class MarkUserAsSpammerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->config('anti_spam.geoip_database', __DIR__ . '/../unit/Validator/test.mmdb');
        $this->extension('archlinux-de-anti-spam', 'flarum-suspend');

        $now = Carbon::now();

        $this->prepareDatabase([
            'users' => [
                ['id' => 1, 'username' => 'moderator', 'email' => 'moderator@example.test', 'is_email_confirmed' => 1],
                ['id' => 2, 'username' => 'spammer', 'email' => 'spammer@example.test', 'is_email_confirmed' => 1],
            ],
            'group_permission' => [
                ['group_id' => 4, 'permission' => 'user.spamblock'],
            ],
            'group_user' => [
                ['user_id' => 1, 'group_id' => 4],
            ],
            'discussions' => [
                [
                    'id' => 1,
                    'title' => 'Spam discussion',
                    'created_at' => $now,
                    'last_posted_at' => $now,
                    'user_id' => 2,
                    'first_post_id' => 1,
                    'comment_count' => 1,
                ],
            ],
            'posts' => [
                [
                    'id' => 1,
                    'discussion_id' => 1,
                    'user_id' => 2,
                    'type' => 'comment',
                    'content' => 'Spam',
                    'created_at' => $now,
                    'number' => 1,
                ],
                [
                    'id' => 2,
                    'discussion_id' => 1,
                    'user_id' => 2,
                    'type' => 'comment',
                    'content' => 'More spam',
                    'created_at' => $now,
                    'number' => 2,
                ],
            ],
        ]);
    }

    public function testItHidesContentAndSuspendsTheSpammer(): void
    {
        $response = $this->send($this->request('POST', '/api/users/2/spamblock', [
            'authenticatedAs' => 1,
        ]));

        $this->assertSame(204, $response->getStatusCode());
        $this->assertNotNull($this->database()->table('discussions')->where('id', 1)->value('hidden_at'));
        $this->assertSame(2, $this->database()->table('posts')->whereNotNull('hidden_at')->count());
        $this->assertNotNull($this->database()->table('users')->where('id', 2)->value('suspended_until'));
    }
}
