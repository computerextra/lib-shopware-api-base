package apibase

type ApiBase struct {
	Shopware_Admin_Api_Url      string
	Shopware_Storefront_Api_Url string
	Username                    string
	Password                    string
	Client_Id                   string
	Client_Secret               string
	Grant_Type                  string
	Store_Api_Sw_Access_Key     string
}

type Payload struct{}

type ShopwareConfig struct {
	store_api_sw_access_key     string
	shopware_storefront_api_url string
}

type Shopware6StoreFrontClientBase struct {
	Config ShopwareConfig
}

type Headers struct {
	ContentType string `json:"Content-Type"`
	Accept      string `json:"Accept"`
	SWAccessKey string `json:"sw-access-key"`
}

type ShopwareAdminApiConfig struct{}

type Shopware6AdminApiClientBase struct {
	Config  ShopwareAdminApiConfig
	token   string
	session string // TODO: Types
}
