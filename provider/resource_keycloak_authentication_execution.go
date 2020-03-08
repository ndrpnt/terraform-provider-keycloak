package provider

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/mrparkers/terraform-provider-keycloak/keycloak"
)

func resourceKeycloakAuthenticationExecution() *schema.Resource {
	return &schema.Resource{
		Create: resourceKeycloakAuthenticationExecutionCreate,
		Read:   resourceKeycloakAuthenticationExecutionRead,
		Delete: resourceKeycloakAuthenticationExecutionDelete,
		Update: resourceKeycloakAuthenticationExecutionUpdate,
		Importer: &schema.ResourceImporter{
			State: resourceKeycloakAuthenticationExecutionImport,
		},
		Schema: map[string]*schema.Schema{
			"realm_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"parent_flow_alias": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"authenticator": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"requirement": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"REQUIRED", "ALTERNATIVE", "OPTIONAL", "CONDITIONAL", "DISABLED"}, false), //OPTIONAL is removed from 8.0.0 onwards
				Default:      "DISABLED",
			},
			"config": {
				Type:     schema.TypeList,
				MaxItems: 1,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"alias": {
							Type:     schema.TypeString,
							Required: true,
							ForceNew: true,
						},
						"config": {
							Type:     schema.TypeMap,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Required: true,
							ForceNew: true,
						},
					},
				},
			},
		},
	}
}

func mapFromDataToAuthenticationExecution(data *schema.ResourceData) *keycloak.AuthenticationExecution {
	authenticationExecution := &keycloak.AuthenticationExecution{
		Id:              data.Id(),
		RealmId:         data.Get("realm_id").(string),
		ParentFlowAlias: data.Get("parent_flow_alias").(string),
		Authenticator:   data.Get("authenticator").(string),
		Requirement:     data.Get("requirement").(string),
	}

	return authenticationExecution
}

func mapFromDataToAuthenticationExecutionConfig(data *schema.ResourceData) *keycloak.AuthenticationExecutionConfig {
	rawConfig, ok := data.GetOk("config")
	if !ok {
		return nil
	}

	config := rawConfig.([]interface{})[0].(map[string]interface{})
	configMap := make(map[string]string)

	for k, v := range config["config"].(map[string]interface{}) {
		configMap[k] = v.(string)
	}

	return &keycloak.AuthenticationExecutionConfig{
		// Id:          rawConfig.(*schema.ResourceData).Id(),
		RealmId:     data.Get("realm_id").(string),
		ExecutionId: data.Id(),
		Alias:       config["alias"].(string),
		Config:      configMap,
	}
}

func mapFromAuthenticationExecutionToData(data *schema.ResourceData, execution *keycloak.AuthenticationExecution, config *keycloak.AuthenticationExecutionConfig) {
	data.SetId(execution.Id)

	data.Set("realm_id", execution.RealmId)
	data.Set("parent_flow_alias", execution.ParentFlowAlias)
	data.Set("authenticator", execution.Authenticator)
	data.Set("requirement", execution.Requirement)

	if config == nil {
		data.Set("config", nil)
	} else {
		configSettings := make(map[string]interface{})
		configSettings["alias"] = config.Alias
		configSettings["config"] = config.Config
		data.Set("config", []interface{}{configSettings})
	}
}

func resourceKeycloakAuthenticationExecutionCreate(data *schema.ResourceData, meta interface{}) error {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	execution := mapFromDataToAuthenticationExecution(data)
	config := mapFromDataToAuthenticationExecutionConfig(data)

	if err := keycloakClient.NewAuthenticationExecution(execution); err != nil {
		return err
	}

	if config != nil {
		if _, err := keycloakClient.NewAuthenticationExecutionConfig(config); err != nil {
			return err
		}
	}

	mapFromAuthenticationExecutionToData(data, execution, config)

	return resourceKeycloakAuthenticationExecutionRead(data, meta)
}

func resourceKeycloakAuthenticationExecutionRead(data *schema.ResourceData, meta interface{}) error {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	realmId := data.Get("realm_id").(string)
	parentFlowAlias := data.Get("parent_flow_alias").(string)
	id := data.Id()

	execution, err := keycloakClient.GetAuthenticationExecution(realmId, parentFlowAlias, id)
	if err != nil {
		return handleNotFoundError(err, data)
	}

	var config *keycloak.AuthenticationExecutionConfig
	if execution.AuthenticationConfig != "" {
		config = &keycloak.AuthenticationExecutionConfig{
			RealmId:     data.Get("realm_id").(string),
			ExecutionId: data.Get("execution_id").(string),
			Id:          data.Id(),
		}

		err := keycloakClient.GetAuthenticationExecutionConfig(config)
		if err != nil {
			return handleNotFoundError(err, data)
		}
	}

	mapFromAuthenticationExecutionToData(data, execution)

	return nil
}

func resourceKeycloakAuthenticationExecutionUpdate(data *schema.ResourceData, meta interface{}) error {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	authenticationExecution := mapFromDataToAuthenticationExecution(data)

	err := keycloakClient.UpdateAuthenticationExecution(authenticationExecution)
	if err != nil {
		return err
	}

	mapFromAuthenticationExecutionToData(data, authenticationExecution)

	return nil
}

func resourceKeycloakAuthenticationExecutionDelete(data *schema.ResourceData, meta interface{}) error {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	realmId := data.Get("realm_id").(string)
	id := data.Id()

	return keycloakClient.DeleteAuthenticationExecution(realmId, id)
}

func resourceKeycloakAuthenticationExecutionImport(d *schema.ResourceData, _ interface{}) ([]*schema.ResourceData, error) {
	parts := strings.Split(d.Id(), "/")

	if len(parts) != 3 {
		return nil, fmt.Errorf("Invalid import. Supported import formats: {{realmId}}/{{parentFlowAlias}}/{{authenticationExecutionId}}")
	}

	d.Set("realm_id", parts[0])
	d.Set("parent_flow_alias", parts[1])
	d.SetId(parts[2])

	return []*schema.ResourceData{d}, nil
}
