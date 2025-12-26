import { Hosts } from '@prisma/client';

import { Injectable } from '@nestjs/common';

import { UniversalConverter } from '@common/converter/universalConverter';

import { HostsEntity } from './entities/hosts.entity';

type HostsWithRelations = Hosts & {
    hostInbounds?: { configProfileInboundUuid: string; configProfileInbounds: { configProfileUuid: string } }[];
};

const modelToEntity = (model: HostsWithRelations): HostsEntity => {
    return new HostsEntity({
        ...model,
        configProfileInboundUuids: model.hostInbounds?.map((i) => i.configProfileInboundUuid) || [],
        configProfileInboundMappings:
            model.hostInbounds?.map((i) => ({
                configProfileInboundUuid: i.configProfileInboundUuid,
                configProfileUuid: i.configProfileInbounds.configProfileUuid,
            })) || [],
    });
};

const entityToModel = (entity: HostsEntity): Hosts => {
    return {
        uuid: entity.uuid,

        viewPosition: entity.viewPosition,
        remark: entity.remark,
        address: entity.address,
        port: entity.port,
        path: entity.path,
        sni: entity.sni,
        host: entity.host,
        alpn: entity.alpn,
        fingerprint: entity.fingerprint,
        securityLayer: entity.securityLayer,
        isDisabled: entity.isDisabled,
        xHttpExtraParams: entity.xHttpExtraParams,
        muxParams: entity.muxParams,
        sockoptParams: entity.sockoptParams,
        serverDescription: entity.serverDescription,
        allowInsecure: entity.allowInsecure,
        shuffleHost: entity.shuffleHost,
        mihomoX25519: entity.mihomoX25519,

        tag: entity.tag,
        isHidden: entity.isHidden,

        overrideSniFromAddress: entity.overrideSniFromAddress,
        keepSniBlank: entity.keepSniBlank,
        configProfileUuid: entity.configProfileUuid,
        configProfileInboundUuid: entity.configProfileInboundUuid,

        vlessRouteId: entity.vlessRouteId,

        xrayJsonTemplateUuid: entity.xrayJsonTemplateUuid,
    };
};

@Injectable()
export class HostsConverter extends UniversalConverter<HostsEntity, Hosts> {
    constructor() {
        super(modelToEntity, entityToModel);
    }
}
