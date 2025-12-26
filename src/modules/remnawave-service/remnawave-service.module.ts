import { Module } from '@nestjs/common';

import { RemnawaveServiceService } from './remnawave-service.service';
import { RemnawaveOutboundCollectorService } from './remnawave-outbound-collector.service';

@Module({
    imports: [],
    controllers: [],
    providers: [RemnawaveServiceService, RemnawaveOutboundCollectorService],
})
export class RemnawaveServiceModule {}
