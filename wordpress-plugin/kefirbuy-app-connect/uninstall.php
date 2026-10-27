<?php
// Removes the app sign-in tokens when the plugin is deleted.
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;
delete_metadata( 'user', 0, '_kb_app_tokens', '', true );
