<?php
return ['driver'=>env('SESSION_DRIVER','file'),'lifetime'=>480,'expire_on_close'=>false,'encrypt'=>true,'files'=>storage_path('framework/sessions'),'cookie'=>'vibenest_app_session','path'=>'/','domain'=>null,'secure'=>true,'http_only'=>true,'same_site'=>'lax'];
