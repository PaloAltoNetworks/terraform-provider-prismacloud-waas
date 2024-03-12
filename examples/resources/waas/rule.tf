resource "prismacloud-waas_rule" "Example" {
  allow_malformed_http_header_names = false
  applications_spec = [
    {
      api_spec = {
        effect      = "disable"
        description = "terraform managed endpoint test - update version 12"
        endpoints = [
          {
            #            base_path     = "*"
            #            exposed_port  = 0
            #            grpc          = false
            #            host          = "*"
            #            http2         = false
            #            internal_port = 0
            #            tls           = false
          }
        ]
        fallback_effect = "disable"
        paths = [
          {
            methods = [
              {
                method = "GET"
                parameters = [
                ]
              }
            ]
            path = "/monkeys"
          }
        ]
        query_param_fallback_effect = "disable"
      }
      app_id = "app-2B49"
      attack_tools = {
        effect = "prevent"
        #        exception_fields = [
        #        ]
      }
      auto_apply_patches_spec = {
        effect = "alert"
      }
      #      ban_duration_minutes         = 5
      body = {
        #        inspection_limit_exceeded_effect = "disable"
        #        inspection_size_bytes            = 131072
        #        skip                             = false
      }
      bot_protection_spec = {
        interstitial_page = false
        js_injection_spec = {
          enabled        = false
          timeout_effect = "disable"
        }
        known_bot_protections_spec = {
          #          archiving              = "alert"
          #          business_analytics     = "disable"
          #          career_search          = "disable"
          #          content_feed_clients   = "disable"
          #          educational            = "disable"
          #          financial              = "disable"
          #          media_search           = "disable"
          #          news                   = "disable"
          #          search_engine_crawlers = "disable"
        }
        re_captcha_spec = {
          all_sessions = true
          enabled      = false
          secret_key = {
            plain = ""
          }
          site_key                 = ""
          success_expiration_hours = 24
          type                     = "checkbox"
        }
        session_validation = "disable"
        unknown_bot_protection_spec = {
          #          api_libraries         = "disable"
          #          bot_impersonation     = "disable"
          #          browser_impersonation = "disable"
          #          generic               = "disable"
          #          http_libraries        = "disable"
          request_anomalies = {
            effect    = "disable"
            threshold = 9
          }
          #         web_automation_tools  = "disable"
          #         web_scrapers          = "disable"
        }
        user_defined_bots = [
        ]
      }
      certificate = {
        plain = ""
      }
      #      clickjacking_enabled         = true
      cmdi = {
        effect = "prevent"
      }
      code_injection = {
        effect = "alert"
        exception_fields = [
        ]
      }
      csrf_enabled = true
      custom_block_response_config = {
        body    = ""
        code    = 0
        enabled = false
      }
      custom_rules = [
      ]
      disable_event_id_header = false
      dos_config = {
        alert_rates = {
          average = 0
          burst   = 0
        }
        ban_rates = {
          average = 0
          burst   = 0
        }
        enabled = false
        match_conditions = [
        ]
        track_session = false
      }
      header_specs = [
      ]
      intel_gathering = {
        info_leakage_effect         = "disable"
        remove_fingerprints_enabled = true
      }
      lfi = {
        effect = "alert"
        exception_fields = [
        ]
      }
      malformed_req = {
        effect = "alert"
        exception_fields = [
        ]
      }
      malicious_upload = {
        allowed_extensions = []
        allowed_file_types = []
        effect             = "disable"
      }
      network_controls = {
        advanced_protection_effect = "alert"
        countries = {
          allow_mode      = true
          enabled         = false
          fallback_effect = "alert"
        }
        subnets = {
          allow_mode      = true
          enabled         = false
          fallback_effect = "alert"
        }
      }
      remote_host_forwarding = {
        enabled = false
        target  = ""
      }
      response_header_specs = [
      ]
      rule_name = "Example"
      #    session_cookie_ban           = false
      #    session_cookie_enabled       = false
      #    session_cookie_same_site     = "None"
      #    session_cookie_secure        = false
      shellshock = {
        effect = "alert"
      }
      sqli = {
        effect = "prevent"
        exception_fields = [
        ]
      }
      #    tls_config                   = {
      #        hsts_config     = {
      #            enabled            = false
      #            include_subdomains = false
      #            max_age_seconds    = 31536000
      #            preload            = false
      #        }
      #        metadata        = {
      #            subject_name = ""
      #            issuer_name = ""
      #            not_after = "0001-01-01T00:00:00Z"
      #        }
      #        min_tls_version = "1.2"
      #    }
      xss = {
        effect = "disable"
        exception_fields = [
        ]
      }
    }
  ]
  auto_protect_ports = true
  collections = [
    {
      name : prismacloud-waas_collection.ContainerExample.name
    }
  ]
  disabled             = true
  name                 = "Example"
  policy_type          = "containerAppFirewall"
  read_timeout_seconds = 5
  skip_api_learning    = false
  traffic_mirroring = {
    enabled = false
  }
  windows = false
}
