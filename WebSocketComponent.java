package com.get.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Component;

import com.get.services.MakeOfferService;
import com.get.services.WebsocketService;
import com.google.gson.Gson;


@Component
public class WebSocketComponent {

	@Autowired
	private SimpMessagingTemplate template;
	
	@Autowired
	private WebsocketService websocketService;
	
	@Autowired
	private MakeOfferService makeOfferService;

	public void webSocketReply(String id) {
		String path = "/queue/notification/" + id;
			
		try
		{
			Map map=websocketService.getNotification(id);
			this.template.convertAndSend(path, new Gson().toJson(map));
		}catch(Exception e)
		{
			
		}
		
			}

}
