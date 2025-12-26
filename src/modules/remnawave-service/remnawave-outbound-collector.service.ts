import axios, { AxiosInstance } from 'axios';

import { Injectable, Logger } from '@nestjs/common';

import { ROUTES } from '@libs/contract/api/routes';

import { getVlessFlow } from '@common/utils/flow/get-vless-flow';
import { IXrayConfig } from '@common/helpers/xray-config/interfaces';
import { InboundObject } from '@common/helpers/xray-config/interfaces/protocols.config';
import { StreamSettingsObject } from '@common/helpers/xray-config/interfaces/transport.config';
import {
    ShadowsocksSettings,
    TrojanSettings,
    VLessSettings,
} from '@common/helpers/xray-config/interfaces/protocol-settings.config';
import { ConfigProfileInboundEntity } from '@modules/config-profiles/entities';

interface RemnawaveApiConfig {
    baseUrl: string;
    apiToken: string;
    hostTags?: string[];
    hostUuids?: string[];
    includeDisabled?: boolean;
    baseClientConfig?: Partial<IXrayConfig>;
}

interface RemnawaveHostResponse {
    uuid: string;
    remark: string;
    address: string;
    port: number;
    path: string | null;
    sni: string | null;
    host: string | null;
    alpn: string | null;
    fingerprint: string | null;
    securityLayer: string;
    xHttpExtraParams: object | null;
    muxParams: object | null;
    sockoptParams: object | null;
    serverDescription: string | null;
    allowInsecure: boolean;
    tag: string | null;
    isHidden: boolean;
    isDisabled: boolean;
    overrideSniFromAddress: boolean;
    keepSniBlank: boolean;
    vlessRouteId: number | null;
    shuffleHost: boolean;
    mihomoX25519: boolean;
    inbound: {
        configProfileUuid: string | null;
        configProfileInboundUuid: string | null;
    };
}

interface RemnawaveHostsApiResponse {
    response: RemnawaveHostResponse[];
}

interface RemnawaveConfigProfileApiResponse {
    response: {
        uuid: string;
        config: object;
        inbounds: ConfigProfileInboundEntity[];
    };
}

interface ClientOutbound {
    tag: string;
    protocol: string;
    settings: unknown;
    streamSettings?: StreamSettingsObject;
    mux?: unknown;
}

@Injectable()
export class RemnawaveOutboundCollectorService {
    private readonly logger = new Logger(RemnawaveOutboundCollectorService.name);

    public async buildCombinedClientConfig(
        options: RemnawaveApiConfig,
    ): Promise<IXrayConfig> {
        const axiosInstance = this.createAxios(options);

        const hosts = await this.fetchHosts(axiosInstance, options);
        const profileCache = new Map<string, RemnawaveConfigProfileApiResponse['response']>();
        const outbounds: ClientOutbound[] = [];

        for (const host of hosts) {
            if (!host.inbound.configProfileUuid || !host.inbound.configProfileInboundUuid) {
                this.logger.warn(
                    `Skipping host ${host.uuid} because it has no attached config profile inbound`,
                );
                continue;
            }

            const profile = await this.getConfigProfile(
                axiosInstance,
                profileCache,
                host.inbound.configProfileUuid,
            );

            if (!profile) {
                continue;
            }

            const inbound = profile.inbounds.find(
                (candidate) => candidate.uuid === host.inbound.configProfileInboundUuid,
            );

            if (!inbound || !inbound.rawInbound) {
                this.logger.warn(
                    `Inbound ${host.inbound.configProfileInboundUuid} is missing for host ${host.uuid}`,
                );
                continue;
            }

            const outbound = this.createOutboundFromInbound(host, inbound.rawInbound as InboundObject);

            if (outbound) {
                if (host.muxParams && Object.keys(host.muxParams).length > 0) {
                    outbound.mux = host.muxParams;
                }

                if (host.sockoptParams && Object.keys(host.sockoptParams).length > 0) {
                    outbound.streamSettings = outbound.streamSettings || {};
                    outbound.streamSettings.sockopt = host.sockoptParams;
                }

                outbounds.push(outbound);
            }
        }

        const baseConfig: IXrayConfig = {
            log: { loglevel: 'warning' },
            inbounds: [
                {
                    tag: 'socks',
                    listen: '127.0.0.1',
                    port: 10808,
                    protocol: 'socks',
                    settings: { udp: true, auth: 'noauth' },
                } as unknown as InboundObject,
            ],
            outbounds: [],
            routing: { rules: [] },
            ...options.baseClientConfig,
        } as IXrayConfig;

        const existingOutbounds: ClientOutbound[] = Array.isArray(baseConfig.outbounds)
            ? (baseConfig.outbounds as ClientOutbound[])
            : [];

        return {
            ...baseConfig,
            outbounds: [...outbounds, ...existingOutbounds],
        };
    }

    private createAxios(options: RemnawaveApiConfig): AxiosInstance {
        return axios.create({
            baseURL: options.baseUrl,
            headers: {
                Authorization: `Bearer ${options.apiToken}`,
            },
        });
    }

    private async fetchHosts(
        axiosInstance: AxiosInstance,
        options: RemnawaveApiConfig,
    ): Promise<RemnawaveHostResponse[]> {
        const url = new URL(ROUTES.HOSTS.GET, options.baseUrl).toString();
        const { data } = await axiosInstance.get<RemnawaveHostsApiResponse>(url);

        return data.response.filter((host) => {
            if (!options.includeDisabled && host.isDisabled) {
                return false;
            }

            if (options.hostTags?.length) {
                return host.tag ? options.hostTags.includes(host.tag) : false;
            }

            if (options.hostUuids?.length) {
                return options.hostUuids.includes(host.uuid);
            }

            return true;
        });
    }

    private async getConfigProfile(
        axiosInstance: AxiosInstance,
        cache: Map<string, RemnawaveConfigProfileApiResponse['response']>,
        uuid: string,
    ): Promise<RemnawaveConfigProfileApiResponse['response'] | null> {
        if (cache.has(uuid)) {
            return cache.get(uuid)!;
        }

        const url = new URL(ROUTES.CONFIG_PROFILES.GET_BY_UUID(uuid), axiosInstance.defaults.baseURL);

        try {
            const { data } = await axiosInstance.get<RemnawaveConfigProfileApiResponse>(url.toString());
            cache.set(uuid, data.response);
            return data.response;
        } catch (error) {
            this.logger.error(`Failed to fetch config profile ${uuid}: ${error}`);
            return null;
        }
    }

    private createOutboundFromInbound(
        host: RemnawaveHostResponse,
        inbound: InboundObject,
    ): ClientOutbound | null {
        const tag = host.tag || inbound.tag;

        switch (inbound.protocol) {
            case 'vless': {
                const settings = inbound.settings as VLessSettings | undefined;
                const client = settings?.clients?.[0];

                if (!client) {
                    this.logger.warn(`VLESS inbound ${inbound.tag} has no clients`);
                    return null;
                }

                return {
                    tag,
                    protocol: 'vless',
                    settings: {
                        vnext: [
                            {
                                address: this.extractAddress(host.address),
                                port: host.port,
                                users: [
                                    {
                                        id: client.id,
                                        encryption: settings?.decryption ?? 'none',
                                        flow: getVlessFlow(inbound),
                                        email: client.email,
                                    },
                                ],
                            },
                        ],
                    },
                    streamSettings: this.mergeStreamSettings(host, inbound.streamSettings),
                };
            }
            case 'trojan': {
                const settings = inbound.settings as TrojanSettings | undefined;
                const client = settings?.clients?.[0];

                if (!client) {
                    this.logger.warn(`Trojan inbound ${inbound.tag} has no clients`);
                    return null;
                }

                return {
                    tag,
                    protocol: 'trojan',
                    settings: {
                        servers: [
                            {
                                address: this.extractAddress(host.address),
                                port: host.port,
                                password: client.password,
                                email: client.email,
                            },
                        ],
                    },
                    streamSettings: this.mergeStreamSettings(host, inbound.streamSettings),
                };
            }
            case 'shadowsocks': {
                const settings = inbound.settings as ShadowsocksSettings | undefined;
                const client = settings?.clients?.[0];

                if (!client) {
                    this.logger.warn(`Shadowsocks inbound ${inbound.tag} has no clients`);
                    return null;
                }

                return {
                    tag,
                    protocol: 'shadowsocks',
                    settings: {
                        servers: [
                            {
                                address: this.extractAddress(host.address),
                                port: host.port,
                                method: client.method,
                                password: client.password,
                                email: client.email,
                            },
                        ],
                    },
                    streamSettings: this.mergeStreamSettings(host, inbound.streamSettings),
                };
            }
            default:
                this.logger.warn(`Unsupported inbound protocol ${inbound.protocol}`);
                return null;
        }
    }

    private mergeStreamSettings(
        host: RemnawaveHostResponse,
        streamSettings?: StreamSettingsObject,
    ): StreamSettingsObject | undefined {
        if (!streamSettings) {
            return undefined;
        }

        const mergedSettings: StreamSettingsObject = JSON.parse(
            JSON.stringify(streamSettings),
        ) as StreamSettingsObject;

        mergedSettings.network = mergedSettings.network || 'tcp';

        if (mergedSettings.security === 'tls' && mergedSettings.tlsSettings) {
            mergedSettings.tlsSettings.serverName =
                host.keepSniBlank === true ? undefined : host.sni || host.address;
            mergedSettings.tlsSettings.alpn = host.alpn ? host.alpn.split(',') : mergedSettings.tlsSettings.alpn;
            mergedSettings.tlsSettings.fingerprint = host.fingerprint ?? mergedSettings.tlsSettings.fingerprint;
            mergedSettings.tlsSettings.allowInsecure = host.allowInsecure;
        }

        if (mergedSettings.security === 'reality' && mergedSettings.realitySettings) {
            mergedSettings.realitySettings.serverNames =
                host.keepSniBlank === true
                    ? mergedSettings.realitySettings.serverNames
                    : host.sni
                      ? [host.sni]
                      : mergedSettings.realitySettings.serverNames;
            if (host.fingerprint) {
                mergedSettings.realitySettings.fingerprint = host.fingerprint;
            }
        }

        switch (mergedSettings.network) {
            case 'ws': {
                const settings = mergedSettings.wsSettings || {};
                mergedSettings.wsSettings = {
                    ...settings,
                    path: host.path || settings.path,
                    headers: {
                        ...((settings as Record<string, unknown>).headers as object),
                        Host: host.host || (settings as Record<string, unknown>).host,
                    },
                };
                break;
            }
            case 'xhttp': {
                const settings = mergedSettings.xhttpSettings || {};
                mergedSettings.xhttpSettings = {
                    ...settings,
                    host: host.host || settings.host,
                    path: host.path || settings.path,
                    extra: host.xHttpExtraParams || settings.extra,
                };
                break;
            }
            default:
                break;
        }

        return mergedSettings;
    }

    private extractAddress(address: string): string {
        if (address.includes(',')) {
            return address.split(',')[0]?.trim();
        }

        return address.trim();
    }
}
