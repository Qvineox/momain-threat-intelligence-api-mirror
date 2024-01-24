// Package swagger GENERATED BY SWAG; DO NOT EDIT
// This file was generated by swaggo/swag
package swagger

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {
            "name": "Yaroslav Lysak",
            "url": "https://t.me/Qvineox"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/blacklists/domain": {
            "delete": {
                "description": "Accepts and deletes single blacklisted domain",
                "tags": [
                    "Blacklists"
                ],
                "summary": "delete blacklisted domain",
                "parameters": [
                    {
                        "description": "record UUID to delete",
                        "name": "id",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/routing.blacklistDeleteParams"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/success.DatabaseResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            }
        },
        "/blacklists/domains": {
            "get": {
                "description": "Gets list of blacklisted domains by filter",
                "tags": [
                    "Blacklists"
                ],
                "summary": "blacklisted domains by filter",
                "parameters": [
                    {
                        "type": "array",
                        "items": {
                            "type": "integer"
                        },
                        "collectionFormat": "multi",
                        "description": "Source type IDs",
                        "name": "source_id",
                        "in": "query"
                    },
                    {
                        "type": "boolean",
                        "description": "Is active",
                        "name": "is_active",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Created timestamp is after",
                        "name": "created_after",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Created timestamp is before",
                        "name": "created_before",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Substring to search",
                        "name": "search_string",
                        "in": "query"
                    },
                    {
                        "type": "integer",
                        "description": "Query limit",
                        "name": "limit",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "integer",
                        "description": "Query offset",
                        "name": "offset",
                        "in": "query"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "array",
                            "items": {
                                "$ref": "#/definitions/entities.BlacklistedDomain"
                            }
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            },
            "put": {
                "description": "Accepts and saves list of blacklisted domains",
                "tags": [
                    "Blacklists"
                ],
                "summary": "insert blacklisted domains",
                "parameters": [
                    {
                        "description": "IPs to save",
                        "name": "hosts",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/routing.blacklistInsertParams"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/success.DatabaseResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            }
        },
        "/blacklists/export/csv": {
            "post": {
                "description": "Accepts filters and returns exported blacklisted hosts in CSV",
                "produces": [
                    "application/csv"
                ],
                "tags": [
                    "Blacklists",
                    "Export"
                ],
                "summary": "exports blacklisted hosts into CSV",
                "parameters": [
                    {
                        "type": "array",
                        "items": {
                            "type": "integer"
                        },
                        "collectionFormat": "multi",
                        "description": "Source type IDs",
                        "name": "source_ids[]",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Created timestamp is after",
                        "name": "created_after",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Created timestamp is before",
                        "name": "created_before",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "file"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            }
        },
        "/blacklists/export/json": {
            "post": {
                "description": "Accepts filters and returns exported blacklisted hosts in JSON",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Blacklists",
                    "Export"
                ],
                "summary": "exports blacklisted hosts into JSON",
                "parameters": [
                    {
                        "type": "array",
                        "items": {
                            "type": "integer"
                        },
                        "collectionFormat": "multi",
                        "description": "Source type IDs",
                        "name": "source_ids",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Created timestamp is after",
                        "name": "created_after",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Created timestamp is before",
                        "name": "created_before",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "file"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            }
        },
        "/blacklists/hosts": {
            "get": {
                "description": "Gets list of blacklisted hosts (all types) by filter",
                "tags": [
                    "Blacklists"
                ],
                "summary": "all hosts by filter",
                "parameters": [
                    {
                        "type": "array",
                        "items": {
                            "type": "integer"
                        },
                        "collectionFormat": "multi",
                        "description": "Source type IDs",
                        "name": "source_id[]",
                        "in": "query"
                    },
                    {
                        "type": "boolean",
                        "description": "Is active",
                        "name": "is_active",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Created timestamp is after",
                        "name": "created_after",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Created timestamp is before",
                        "name": "created_before",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "value to search",
                        "name": "search_string",
                        "in": "query"
                    },
                    {
                        "type": "integer",
                        "description": "Query limit",
                        "name": "limit",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "integer",
                        "description": "Query offset",
                        "name": "offset",
                        "in": "query"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "array",
                            "items": {
                                "$ref": "#/definitions/entities.BlacklistedHost"
                            }
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            }
        },
        "/blacklists/import/csv": {
            "post": {
                "description": "Accepts and imports blacklisted hosts from CSV file",
                "tags": [
                    "Blacklists",
                    "Import"
                ],
                "summary": "import blacklisted hosts from CSV file",
                "parameters": [
                    {
                        "type": "file",
                        "description": "file to import",
                        "name": "file_upload",
                        "in": "formData",
                        "required": true
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/success.DatabaseResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            }
        },
        "/blacklists/import/stix": {
            "post": {
                "description": "Accepts and imports blacklisted hosts from STIX 2.0 file",
                "consumes": [
                    "multipart/form-data"
                ],
                "tags": [
                    "Blacklists",
                    "Import"
                ],
                "summary": "import blacklisted hosts from file (STIX 2.0)",
                "parameters": [
                    {
                        "type": "file",
                        "description": "files to import",
                        "name": "file_upload",
                        "in": "formData",
                        "required": true
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/success.DatabaseResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            }
        },
        "/blacklists/ip": {
            "delete": {
                "description": "Accepts and deletes single blacklisted IP",
                "tags": [
                    "Blacklists"
                ],
                "summary": "delete blacklisted ip",
                "parameters": [
                    {
                        "description": "record UUID to delete",
                        "name": "id",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/routing.blacklistDeleteParams"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/success.DatabaseResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            }
        },
        "/blacklists/ips": {
            "get": {
                "description": "Gets list of blacklisted ips by filter",
                "tags": [
                    "Blacklists"
                ],
                "summary": "blacklisted ips by filter",
                "parameters": [
                    {
                        "type": "array",
                        "items": {
                            "type": "integer"
                        },
                        "collectionFormat": "multi",
                        "description": "Source type IDs",
                        "name": "source_id",
                        "in": "query"
                    },
                    {
                        "type": "boolean",
                        "description": "Is active",
                        "name": "is_active",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Created timestamp is after",
                        "name": "created_after",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Created timestamp is before",
                        "name": "created_before",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "CIDR to search (must include IP/MASK)",
                        "name": "search_string",
                        "in": "query"
                    },
                    {
                        "type": "integer",
                        "description": "Query limit",
                        "name": "limit",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "integer",
                        "description": "Query offset",
                        "name": "offset",
                        "in": "query"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "array",
                            "items": {
                                "$ref": "#/definitions/entities.BlacklistedIP"
                            }
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            },
            "put": {
                "description": "Accepts and saves list of blacklisted IPs",
                "tags": [
                    "Blacklists"
                ],
                "summary": "insert blacklisted ips",
                "parameters": [
                    {
                        "description": "IPs to save",
                        "name": "hosts",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/routing.blacklistInsertParams"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/success.DatabaseResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            }
        },
        "/blacklists/sources": {
            "get": {
                "description": "Returns all available blacklist data sources",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Blacklists"
                ],
                "summary": "returns blacklist sources",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "array",
                            "items": {
                                "$ref": "#/definitions/entities.BlacklistSource"
                            }
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            }
        },
        "/blacklists/stats": {
            "get": {
                "description": "Returns data containing overall amount of blacklisted entities",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Blacklists"
                ],
                "summary": "returns amount of blacklisted entities",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/routing.BlacklistedStatistics"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            }
        },
        "/blacklists/url": {
            "delete": {
                "description": "Accepts and deletes single blacklisted URL",
                "tags": [
                    "Blacklists"
                ],
                "summary": "delete blacklisted URL",
                "parameters": [
                    {
                        "description": "record UUID to delete",
                        "name": "id",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/routing.blacklistDeleteParams"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/success.DatabaseResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            }
        },
        "/blacklists/urls": {
            "get": {
                "description": "Gets list of blacklisted URLs by filter",
                "tags": [
                    "Blacklists"
                ],
                "summary": "blacklisted urls by filter",
                "parameters": [
                    {
                        "type": "array",
                        "items": {
                            "type": "integer"
                        },
                        "collectionFormat": "multi",
                        "description": "Source type IDs",
                        "name": "source_id",
                        "in": "query"
                    },
                    {
                        "type": "boolean",
                        "description": "Is active",
                        "name": "is_active",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Created timestamp is after",
                        "name": "created_after",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Created timestamp is before",
                        "name": "created_before",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Substring to search",
                        "name": "search_string",
                        "in": "query"
                    },
                    {
                        "type": "integer",
                        "description": "Query limit",
                        "name": "limit",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "integer",
                        "description": "Query offset",
                        "name": "offset",
                        "in": "query"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "array",
                            "items": {
                                "$ref": "#/definitions/entities.BlacklistedURL"
                            }
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            },
            "put": {
                "description": "Accepts and saves list of blacklisted urls",
                "tags": [
                    "Blacklists"
                ],
                "summary": "insert blacklisted urls",
                "parameters": [
                    {
                        "description": "URLs to save",
                        "name": "hosts",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/routing.blacklistInsertParams"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/success.DatabaseResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/error.APIError"
                        }
                    }
                }
            }
        },
        "/maintenance/ping": {
            "get": {
                "description": "Gets info about application availability and status",
                "tags": [
                    "Maintenance"
                ],
                "summary": "application availability and status",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/entities.AppStatus"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "entities.AppStatus": {
            "type": "object",
            "properties": {
                "Status": {
                    "type": "string"
                }
            }
        },
        "entities.BlacklistSource": {
            "type": "object",
            "properties": {
                "CreatedAt": {
                    "type": "string"
                },
                "DeletedAt": {
                    "$ref": "#/definitions/gorm.DeletedAt"
                },
                "Description": {
                    "type": "string"
                },
                "ID": {
                    "type": "integer"
                },
                "Name": {
                    "type": "string"
                },
                "UpdatedAt": {
                    "type": "string"
                }
            }
        },
        "entities.BlacklistedDomain": {
            "type": "object",
            "properties": {
                "CreatedAt": {
                    "type": "string"
                },
                "DeletedAt": {
                    "$ref": "#/definitions/gorm.DeletedAt"
                },
                "Description": {
                    "type": "string"
                },
                "Source": {
                    "description": "Defines source from where blacklisted host was added",
                    "$ref": "#/definitions/entities.BlacklistSource"
                },
                "SourceID": {
                    "type": "integer"
                },
                "URN": {
                    "type": "string"
                },
                "UUID": {
                    "type": "string"
                },
                "UpdatedAt": {
                    "type": "string"
                }
            }
        },
        "entities.BlacklistedHost": {
            "type": "object",
            "properties": {
                "CreatedAt": {
                    "type": "string"
                },
                "DeletedAt": {
                    "$ref": "#/definitions/gorm.DeletedAt"
                },
                "Description": {
                    "type": "string"
                },
                "Host": {
                    "type": "string"
                },
                "Source": {
                    "description": "Defines source from where blacklisted host was added",
                    "$ref": "#/definitions/entities.BlacklistSource"
                },
                "SourceID": {
                    "type": "integer"
                },
                "Status": {
                    "type": "string"
                },
                "Type": {
                    "description": "domain, url or IP",
                    "type": "string"
                },
                "UUID": {
                    "type": "string"
                },
                "UpdatedAt": {
                    "type": "string"
                }
            }
        },
        "entities.BlacklistedIP": {
            "type": "object",
            "properties": {
                "CreatedAt": {
                    "type": "string"
                },
                "DeletedAt": {
                    "$ref": "#/definitions/gorm.DeletedAt"
                },
                "Description": {
                    "type": "string"
                },
                "IPAddress": {
                    "$ref": "#/definitions/pgtype.Inet"
                },
                "Source": {
                    "description": "Defines source from where blacklisted host was added",
                    "$ref": "#/definitions/entities.BlacklistSource"
                },
                "SourceID": {
                    "type": "integer"
                },
                "UUID": {
                    "type": "string"
                },
                "UpdatedAt": {
                    "type": "string"
                }
            }
        },
        "entities.BlacklistedURL": {
            "type": "object",
            "properties": {
                "CreatedAt": {
                    "type": "string"
                },
                "DeletedAt": {
                    "$ref": "#/definitions/gorm.DeletedAt"
                },
                "Description": {
                    "type": "string"
                },
                "MD5": {
                    "type": "string"
                },
                "Source": {
                    "description": "Defines source from where blacklisted host was added",
                    "$ref": "#/definitions/entities.BlacklistSource"
                },
                "SourceID": {
                    "type": "integer"
                },
                "URL": {
                    "type": "string"
                },
                "UUID": {
                    "type": "string"
                },
                "UpdatedAt": {
                    "type": "string"
                }
            }
        },
        "error.APIError": {
            "type": "object",
            "properties": {
                "ErrorCode": {
                    "type": "integer"
                },
                "ErrorMessage": {
                    "type": "string"
                },
                "ErrorModule": {
                    "type": "string"
                },
                "StatusCode": {
                    "type": "integer"
                }
            }
        },
        "gorm.DeletedAt": {
            "type": "object",
            "properties": {
                "time": {
                    "type": "string"
                },
                "valid": {
                    "description": "Valid is true if Time is not NULL",
                    "type": "boolean"
                }
            }
        },
        "net.IPNet": {
            "type": "object",
            "properties": {
                "ip": {
                    "description": "network number",
                    "type": "array",
                    "items": {
                        "type": "integer"
                    }
                },
                "mask": {
                    "description": "network mask",
                    "type": "array",
                    "items": {
                        "type": "integer"
                    }
                }
            }
        },
        "pgtype.Inet": {
            "type": "object",
            "properties": {
                "ipnet": {
                    "$ref": "#/definitions/net.IPNet"
                },
                "status": {
                    "type": "integer"
                }
            }
        },
        "routing.BlacklistedStatistics": {
            "type": "object",
            "properties": {
                "ByDate": {
                    "type": "object",
                    "properties": {
                        "Dates": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        },
                        "Domains": {
                            "type": "array",
                            "items": {
                                "type": "integer"
                            }
                        },
                        "IPs": {
                            "type": "array",
                            "items": {
                                "type": "integer"
                            }
                        },
                        "URLs": {
                            "type": "array",
                            "items": {
                                "type": "integer"
                            }
                        }
                    }
                },
                "LastEval": {
                    "type": "string"
                },
                "TotalDomains": {
                    "type": "integer"
                },
                "TotalIPs": {
                    "type": "integer"
                },
                "TotalURLs": {
                    "type": "integer"
                }
            }
        },
        "routing.blacklistDeleteParams": {
            "type": "object",
            "properties": {
                "uuid": {
                    "type": "string"
                }
            }
        },
        "routing.blacklistInsertParams": {
            "type": "object",
            "required": [
                "hosts"
            ],
            "properties": {
                "hosts": {
                    "description": "issue: https://github.com/gin-gonic/gin/issues/3436",
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "required": [
                            "host",
                            "source_id"
                        ],
                        "properties": {
                            "description": {
                                "type": "string"
                            },
                            "host": {
                                "type": "string"
                            },
                            "source_id": {
                                "type": "integer"
                            }
                        }
                    }
                }
            }
        },
        "success.DatabaseResponse": {
            "type": "object",
            "properties": {
                "RowsAffected": {
                    "type": "integer"
                },
                "StatusCode": {
                    "type": "integer"
                },
                "Warnings": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "0.0.3",
	Host:             "localhost:7090",
	BasePath:         "/api/v1",
	Schemes:          []string{},
	Title:            "Domain Threat Intelligence API",
	Description:      "API provided by DTI project",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
