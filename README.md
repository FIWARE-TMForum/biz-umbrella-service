# Umbrella Service BAE plugin

This repository includes an asset type extension for the FIWARE [Business API Ecosystem GE](https://github.com/FIWARE-TMForum/Business-API-Ecosystem).

This BAE plugin supports the monetization of API services secured with an instance of [Apinf Umbrella](https://github.com/apinf/apinf-umbrella).

This BAE plugin has been tested in BAE versions 7.4.0 and 7.6.0

This plugin supports the following meta data to be included as part of BAE products:

* **Required Headers**: Required headers field as included in the API Umbrella sub-path configuration.
* **Authorization Method**: Whether user access to backend service is controlled using FIWARE IDM roles or API Umbrella native roles
* **Acquisition Role**: Role to be granted to customers
* **Access to sub-paths allowed**: If true, customers will be able to access to any sub-path of the monetized service
* **Additional query strings allowed**: If true, customers will be able to call the service with different query strings as the included in the asset URL
* **Admin API Key**: API key to be used by the BAE to access to the API Umbrella admin API
* **Admin Auth Token**: Admin token to be used by the BAE to access to the Umbrella admin API

This plugin supports accounting based on *Api call* units.
