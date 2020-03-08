package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/mrparkers/terraform-provider-keycloak/keycloak"
)

func TestAccKeycloakAuthenticationExecution_basic(t *testing.T) {
	realmName := "terraform-r-" + acctest.RandString(10)
	var execution1, execution2 keycloak.AuthenticationExecution

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCheckKeycloakAuthenticationExecutionDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKeycloakAuthenticationExecution(realmName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKeycloakAuthenticationExecutionExists("keycloak_authentication_execution.execution", &execution1),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "realm_id", realmName),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "parent_flow_alias", "some-flow-alias"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "authenticator", "auth-cookie"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "requirement", "DISABLED"),
				),
			},
			{
				Config: testAccKeycloakAuthenticationExecutionUpdatedRequirement(realmName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKeycloakAuthenticationExecutionExists("keycloak_authentication_execution.execution", &execution2),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "realm_id", realmName),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "parent_flow_alias", "some-flow-alias"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "authenticator", "auth-cookie"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "requirement", "REQUIRED"),
					testAccCheckKeycloakAuthenticationExecutionForceNew(&execution1, &execution2, false),
				),
			},
		},
	})
}

func TestAccKeycloakAuthenticationExecution_updateForcesNew(t *testing.T) {
	realmName := "terraform-r-" + acctest.RandString(10)
	var execution1, execution2 keycloak.AuthenticationExecution

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCheckKeycloakAuthenticationExecutionDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKeycloakAuthenticationExecution(realmName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKeycloakAuthenticationExecutionExists("keycloak_authentication_execution.execution", &execution1),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "realm_id", realmName),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "parent_flow_alias", "some-flow-alias"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "authenticator", "auth-cookie"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "requirement", "DISABLED"),
				),
			},
			{
				Config: testAccKeycloakAuthenticationExecutionUpdatedAuthenticator(realmName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKeycloakAuthenticationExecutionExists("keycloak_authentication_execution.execution", &execution2),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "realm_id", realmName),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "parent_flow_alias", "some-flow-alias"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "authenticator", "identity-provider-redirector"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "requirement", "DISABLED"),
					testAccCheckKeycloakAuthenticationExecutionForceNew(&execution1, &execution2, true),
				),
			},
		},
	})
}

func TestAccKeycloakAuthenticationExecution_updateConfig(t *testing.T) {
	realmName := "terraform-r-" + acctest.RandString(10)
	var execution1, execution2, execution3, execution4 keycloak.AuthenticationExecution

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCheckKeycloakAuthenticationExecutionDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKeycloakAuthenticationExecutionUpdatedAuthenticator(realmName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKeycloakAuthenticationExecutionExists("keycloak_authentication_execution.execution", &execution1),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "realm_id", realmName),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "parent_flow_alias", "some-flow-alias"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "authenticator", "identity-provider-redirector"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "requirement", "DISABLED"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "config.#", "0"),
				),
			},
			{
				Config: testAccKeycloakAuthenticationExecutionWithConfig(realmName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKeycloakAuthenticationExecutionExists("keycloak_authentication_execution.execution", &execution2),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "realm_id", realmName),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "parent_flow_alias", "some-flow-alias"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "authenticator", "identity-provider-redirector"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "requirement", "DISABLED"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "config.#", "1"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "config.0.alias", "some-config-alias"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "config.0.config.%", "1"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "config.0.config.defaultProvider", "some-config-default-idp"),
					testAccCheckKeycloakAuthenticationExecutionForceNew(&execution1, &execution2, true),
				),
			},
			{
				Config: testAccKeycloakAuthenticationExecutionWithConfigUpdatedAlias(realmName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKeycloakAuthenticationExecutionExists("keycloak_authentication_execution.execution", &execution3),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "realm_id", realmName),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "parent_flow_alias", "some-flow-alias"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "authenticator", "identity-provider-redirector"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "requirement", "DISABLED"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "config.#", "1"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "config.0.alias", "some-updated-config-alias"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "config.0.config.%", "1"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "config.0.config.defaultProvider", "some-config-default-idp"),
					testAccCheckKeycloakAuthenticationExecutionForceNew(&execution2, &execution3, true),
				),
			},
			{
				Config: testAccKeycloakAuthenticationExecutionUpdatedAuthenticator(realmName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKeycloakAuthenticationExecutionExists("keycloak_authentication_execution.execution", &execution2),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "realm_id", realmName),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "parent_flow_alias", "some-flow-alias"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "authenticator", "identity-provider-redirector"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "requirement", "DISABLED"),
					resource.TestCheckResourceAttr("keycloak_authentication_execution.execution", "config.#", "0"),
					testAccCheckKeycloakAuthenticationExecutionForceNew(&execution3, &execution4, true),
				),
			},
		},
	})
}

func TestAccKeycloakAuthenticationExecution_import(t *testing.T) {
	realmName := "terraform-r-" + acctest.RandString(10)

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCheckKeycloakAuthenticationExecutionDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKeycloakAuthenticationExecution(realmName),
			},
			{
				ResourceName:      "keycloak_authentication_execution.execution",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: getExecutionImportId("keycloak_authentication_execution.execution"),
			},
		},
	})
}

func getExecutionImportId(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("resource %s not found", resourceName)
		}

		realmId := rs.Primary.Attributes["realm_id"]
		parentFlowAlias := rs.Primary.Attributes["parent_flow_alias"]
		id := rs.Primary.ID

		return fmt.Sprintf("%s/%s/%s", realmId, parentFlowAlias, id), nil
	}
}

func testAccCheckKeycloakAuthenticationExecutionExists(resourceName string, execution *keycloak.AuthenticationExecution) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}

		realmId := rs.Primary.Attributes["realm_id"]
		parentAlias := rs.Primary.Attributes["parent_flow_alias"]
		id := rs.Primary.ID

		keycloakClient := testAccProvider.Meta().(*keycloak.KeycloakClient)
		tmpExecution, err := keycloakClient.GetAuthenticationExecution(realmId, parentAlias, id)
		if err != nil {
			return fmt.Errorf("error fetching authentication execution: %v", err)
		}

		*execution = *tmpExecution
		return nil
	}
}

func testAccCheckKeycloakAuthenticationExecutionDestroy(s *terraform.State) error {
	keycloakClient := testAccProvider.Meta().(*keycloak.KeycloakClient)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "keycloak_authentication_execution" {
			continue
		}

		realmId := rs.Primary.Attributes["realm_id"]
		parentAlias := rs.Primary.Attributes["parent_flow_alias"]
		id := rs.Primary.ID

		if _, err := keycloakClient.GetAuthenticationExecution(realmId, parentAlias, id); err == nil {
			return fmt.Errorf("qauthentication execution still exists")
		} else if !keycloak.ErrorIs404(err) {
			return fmt.Errorf("could not fetch authentication execution: %v", err)
		}
	}

	return nil
}

func testAccCheckKeycloakAuthenticationExecutionForceNew(old, new *keycloak.AuthenticationExecution, wantNew bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if wantNew && old.Id == new.Id {
			return fmt.Errorf("expecting authentication execution ID to differ, got %+v and %+v", old, new)
		}
		if !wantNew && old.Id != new.Id {
			return fmt.Errorf("expecting authentication execution ID to be equal, got %+v and %+v", old, new)
		}
		return nil
	}
}

func testAccKeycloakAuthenticationExecution(realm string) string {
	return fmt.Sprintf(`
resource "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_authentication_flow" "flow" {
	realm_id = "${keycloak_realm.realm.id}"
	alias    = "some-flow-alias"
}

resource "keycloak_authentication_execution" "execution" {
	realm_id          = "${keycloak_realm.realm.id}"
	parent_flow_alias = "${keycloak_authentication_flow.flow.alias}"
	authenticator     = "auth-cookie"
}`, realm)
}

func testAccKeycloakAuthenticationExecutionUpdatedRequirement(realm string) string {
	return fmt.Sprintf(`
resource "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_authentication_flow" "flow" {
	realm_id = "${keycloak_realm.realm.id}"
	alias    = "some-flow-alias"
}

resource "keycloak_authentication_execution" "execution" {
	realm_id          = "${keycloak_realm.realm.id}"
	parent_flow_alias = "${keycloak_authentication_flow.flow.alias}"
	authenticator     = "auth-cookie"
	requirement       = "REQUIRED"
}`, realm)
}

func testAccKeycloakAuthenticationExecutionUpdatedAuthenticator(realm string) string {
	return fmt.Sprintf(`
resource "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_authentication_flow" "flow" {
	realm_id = "${keycloak_realm.realm.id}"
	alias    = "some-flow-alias"
}

resource "keycloak_authentication_execution" "execution" {
	realm_id          = "${keycloak_realm.realm.id}"
	parent_flow_alias = "${keycloak_authentication_flow.flow.alias}"
	authenticator     = "identity-provider-redirector"
}`, realm)
}

func testAccKeycloakAuthenticationExecutionWithConfig(realm string) string {
	return fmt.Sprintf(`
resource "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_authentication_flow" "flow" {
	realm_id = "${keycloak_realm.realm.id}"
	alias    = "some-flow-alias"
}

resource "keycloak_authentication_execution" "execution" {
	realm_id          = "${keycloak_realm.realm.id}"
	parent_flow_alias = "${keycloak_authentication_flow.flow.alias}"
	authenticator     = "identity-provider-redirector"
	config {
		alias = "some-config-alias"
		config = {
			defaultProvider = "some-config-default-idp"
		}
	}
}`, realm)
}

func testAccKeycloakAuthenticationExecutionWithConfigUpdatedAlias(realm string) string {
	return fmt.Sprintf(`
resource "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_authentication_flow" "flow" {
	realm_id = "${keycloak_realm.realm.id}"
	alias    = "some-flow-alias"
}

resource "keycloak_authentication_execution" "execution" {
	realm_id          = "${keycloak_realm.realm.id}"
	parent_flow_alias = "${keycloak_authentication_flow.flow.alias}"
	authenticator     = "identity-provider-redirector"
	config {
		alias = "some-updated-config-alias"
		config = {
			defaultProvider = "some-config-default-idp"
		}
	}
}`, realm)
}
