# keycloak-social-ding

* 安装步骤:
* 添加jar包到Keycloak服务:
  * `$ cp target/keycloak-social-ding-${version}.jar _KEYCLOAK_HOME_/standalon/deployments

* 添加模板文件到Keycloak服务:
  1. `$ cp templates/realm-identity-provider-ding.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials`
  1. `$ cp templates/realm-identity-provider-ding-ext.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials`

