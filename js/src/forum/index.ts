import app from 'flarum/forum/app';
import addSpamblockControls from './addSpamblockControls';

app.initializers.add('archlinux-de/anti-spam', () => {
  addSpamblockControls();
});
