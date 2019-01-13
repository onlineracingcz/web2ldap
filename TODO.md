Known issues
============

This lists small issues and open questions too unimportant for the roadmap.

web2ldap 1.4
------------

  - Uploading attribute *jpegPhoto* does not work although uploading other
    binary attributes seems to work.

  - Shall *sp_entity* also be used to escape single spaces?

  - instead of passing discrete variables env, form, ls, sid, schema etc.
    around only one variable *app*, an instance var of
    *web2ldap.app.handler.AppHandler*, should be used everywhere with the
    above variables as instance attributes.