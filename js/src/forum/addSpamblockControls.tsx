import app from 'flarum/forum/app';
import { extend } from 'flarum/common/extend';
import Button from 'flarum/common/components/Button';
import User from 'flarum/common/models/User';
import UserControls from 'flarum/forum/utils/UserControls';
import ItemList from 'flarum/common/utils/ItemList';
import extractText from 'flarum/common/utils/extractText';
import type Mithril from 'mithril';

export default function addSpamblockControls() {
  extend(UserControls, 'moderationControls', function (items: ItemList<Mithril.Children>, user: User) {
    if (!user.attribute<boolean>('canSpamblock')) return;

    items.add(
      'spammer',
      <Button
        icon="fas fa-shield-alt"
        onclick={() => {
          if (!confirm(extractText(app.translator.trans('archlinux-de-anti-spam.forum.user_controls.spammer_confirmation')))) return;

          app
            .request({
              method: 'POST',
              url: `${app.forum.attribute('apiUrl')}/users/${user.id()}/spamblock`,
            })
            .then(() => window.location.reload());
        }}
      >
        {app.translator.trans('archlinux-de-anti-spam.forum.user_controls.spammer_button')}
      </Button>
    );
  });
}
