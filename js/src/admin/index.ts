import app from 'flarum/admin/app';

app.initializers.add('archlinux-de/anti-spam', () => {
  app.extensionData.for('archlinux-de-anti-spam').registerPermission(
    {
      icon: 'fas fa-shield-alt',
      label: app.translator.trans('archlinux-de-anti-spam.admin.permissions.spamblock_users_label'),
      permission: 'user.spamblock',
    },
    'moderate'
  );
});
